"""Standalone vendor-library sniffing check. No backend imports, TUN or broker.

Run in Dockerfile.incy-test's disposable container, overriding its entrypoint:
python3 /repo/tests/incy_ferrum_check.py
Native libraries are mounted under /inspect; the image provides upstream Xray.
"""

from __future__ import annotations

import argparse
import ctypes
import http.client
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from incy_artifacts import verify_artifacts

LIBRARY = "/inspect/lib/app/resources/bin/libincycore.so"
ENTRY = "11.0.0.2"
TARGET = "11.0.0.1"
BODY = "ferrum-test"


def native_case(sniffing: str, padding: int) -> dict:
    assert 0 not in os.getresuid()
    status = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    assert all(int(status[field], 16) == 0 for field in ("CapPrm", "CapEff", "CapAmb"))
    library = ctypes.CDLL(LIBRARY)
    library.IncycoreXrayStart.argtypes = [ctypes.c_char_p]
    library.IncycoreXrayStart.restype = ctypes.c_void_p
    library.IncycoreXrayStop.argtypes = []
    library.IncycoreXrayStop.restype = ctypes.c_void_p
    library.IncycoreFreeString.argtypes = [ctypes.c_void_p]
    library.IncycoreFreeString.restype = None

    def checked(error: int | None) -> None:
        if error is not None:
            try:
                message = ctypes.string_at(error).decode(errors="replace")
            finally:
                library.IncycoreFreeString(error)
            raise OSError(message)

    config = {
        "inbounds": [
            {
                "tag": "test-in",
                "listen": "127.0.0.1",
                "port": 18090,
                "protocol": "http",
                "sniffing": {
                    "enabled": sniffing != "off",
                    "routeOnly": sniffing == "route-only",
                    "destOverride": ["http", "tls", "quic"],
                },
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [
                        {
                            "address": ENTRY,
                            "port": 8389,
                            "method": "aes-128-gcm",
                            "password": "synthetic-test-only",
                        }
                    ],
                },
            }
        ],
        "routing": {"rules": [{"network": "tcp,udp", "outboundTag": "proxy"}]},
    }
    connection = http.client.HTTPConnection("127.0.0.1", 18090, timeout=3)
    result: dict = {"sniffing": sniffing, "padding": padding}
    try:
        checked(library.IncycoreXrayStart(json.dumps(config).encode()))
        connection.set_tunnel(TARGET, 18080)
        connection.request("GET", "/", headers={"X-Pad": "x" * padding})
        response = connection.getresponse()
        body = response.read().decode()
        result.update(
            outcome="ok" if response.status == 200 and body == BODY else "bad-response",
            status=response.status,
            body=body,
        )
    except OSError as exc:
        result.update(outcome="error", error=f"{type(exc).__name__}: {exc}")
    finally:
        connection.close()
        checked(library.IncycoreXrayStop())
    return result


def wait_port(host: str, port: int) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError(f"Test service {host}:{port} did not start")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=("off", "route-only", "override"))
    parser.add_argument("--padding", type=int, default=0)
    args = parser.parse_args()
    verify_artifacts(Path("/inspect"))
    if args.case:
        print("RESULT " + json.dumps(native_case(args.case, args.padding)), flush=True)
        return
    assert os.getuid() == 0
    for command in (
        ["link", "set", "lo", "up"],
        ["addr", "add", ENTRY + "/32", "dev", "lo"],
        ["addr", "add", TARGET + "/32", "dev", "lo"],
    ):
        subprocess.run(["ip", *command], check=True, capture_output=True, timeout=5)
    server_config = {
        "inbounds": [
            {
                "listen": ENTRY,
                "port": 8389,
                "protocol": "shadowsocks",
                "settings": {"method": "aes-128-gcm", "password": "synthetic-test-only"},
            }
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        "routing": {"rules": [{"network": "tcp,udp", "outboundTag": "direct"}]},
    }
    server = subprocess.Popen(
        ["/opt/xray/26.9.30/xray", "run", "-config", "stdin:"],
        user=65534,
        group=65534,
        extra_groups=[],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    http = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from http.server import BaseHTTPRequestHandler, HTTPServer; "
            "H=type('H',(BaseHTTPRequestHandler,),{'do_GET':lambda s:"
            "(s.send_response(200),s.end_headers(),s.wfile.write(b'ferrum-test'))}); "
            "HTTPServer(('11.0.0.1',18080),H).serve_forever()",
        ],
        user=65534,
        group=65534,
        extra_groups=[],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        assert server.stdin is not None
        server.stdin.write(json.dumps(server_config).encode())
        server.stdin.close()
        wait_port(ENTRY, 8389)
        wait_port(TARGET, 18080)
        results = []
        for mode, padding in (
            ("off", 0),
            ("route-only", 0),
            ("override", 0),
            ("route-only", 16384),
        ):
            completed = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--case",
                    mode,
                    "--padding",
                    str(padding),
                ],
                user=65534,
                group=65534,
                extra_groups=[],
                capture_output=True,
                text=True,
                timeout=12,
                check=True,
            )
            record = next(
                line.removeprefix("RESULT ")
                for line in completed.stdout.splitlines()
                if line.startswith("RESULT ")
            )
            result = json.loads(record)
            results.append(result)
            print(json.dumps(result), flush=True)
        assert results[0]["outcome"] == "ok", "Negative control: basic SS transport is broken"
    finally:
        for process in (server, http):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if server.stderr:
            server.stderr.close()


if __name__ == "__main__":
    main()
