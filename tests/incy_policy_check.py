"""Explicit root-in-container check of actual Ferrum + broker + nft proxy/direct policy.

Not collected by pytest. Never use this script as a production privileged helper.
"""

from __future__ import annotations

import json
import os
import select
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from happ.constants import KILLSWITCH_MARK
from incy import broker, network
from incy.worker import Core


def run_case(library: str, proxy: bool) -> None:
    with socket.socket() as origin, socket.socket() as reservation:
        origin.bind(("127.0.0.1", 0))
        origin.listen()
        origin.settimeout(2)
        target = origin.getsockname()[1]
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        reservation.close()
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        ready_r, ready_w = os.pipe()
        pid = os.fork()
        if pid == 0:
            server.close()
            origin.close()
            os.close(ready_r)
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
            core = Core(library)
            core.set_socket_protector(broker.Client(client).protect)
            config = {
                "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "http"}],
                "outbounds": [
                    {
                        "protocol": "freedom",
                        "tag": "dns-direct" if proxy else "direct",
                        "streamSettings": {
                            "sockopt": {
                                "mark": KILLSWITCH_MARK if proxy else 0,
                                # A subscription's own priority must not grant direct a bypass.
                                "customSockopt": [
                                    {"level": "1", "opt": "12", "value": "6", "type": "int"}
                                ],
                            }
                        },
                    }
                ],
            }
            stopped = threading.Event()
            signal.signal(signal.SIGTERM, lambda *_: stopped.set())
            try:
                core.start(network.prepare_config(config))
                os.write(ready_w, b"1")
                os.close(ready_w)
                while core.running() and not stopped.wait(0.1):
                    pass
            finally:
                core.stop()
                client.close()
            os._exit(0)
        client.close()
        os.close(ready_w)
        thread = threading.Thread(
            target=broker.serve,
            args=(server, lambda sock: network.protect_socket(sock, "lo")),
            daemon=True,
        )
        thread.start()
        try:
            assert select.select([ready_r], [], [], 5)[0], "core startup timed out"
            assert os.read(ready_r, 1) == b"1", "core failed before readiness"
            with socket.create_connection(("127.0.0.1", port), timeout=2) as request:
                request.sendall(
                    f"GET http://127.0.0.1:{target}/ HTTP/1.1\r\nHost: localhost\r\n\r\n".encode()
                )
                if proxy:
                    connection, _ = origin.accept()
                    with connection:
                        connection.settimeout(2)
                        assert b"GET / HTTP/1.1" in connection.recv(8192)
                        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    assert b"200 OK" in request.recv(4096)
                else:
                    try:
                        connection, _ = origin.accept()
                    except TimeoutError:
                        pass
                    else:
                        connection.close()
                        raise AssertionError("direct traffic bypassed the policy")
            print(f"{'proxy accepted' if proxy else 'direct blocked'}: OK", flush=True)
        finally:
            os.close(ready_r)
            os.kill(pid, signal.SIGTERM)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                child, _ = os.waitpid(pid, os.WNOHANG)
                if child:
                    break
                time.sleep(0.05)
            else:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                raise AssertionError("core did not stop")
            thread.join(2)
            server.close()
            assert not thread.is_alive(), "broker did not stop"


def main() -> None:
    if not Path("/.dockerenv").is_file() or os.geteuid() != 0:
        raise RuntimeError("Run only as root inside a disposable --network none Docker container")
    links = json.loads(subprocess.check_output(["ip", "-j", "link", "show"]))
    if [link["ifname"] for link in links] != ["lo"]:
        raise RuntimeError("Expected a fresh network namespace containing only lo")
    library = sys.argv[1]
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    policy = f"""table inet incy_test {{
 chain output {{ type filter hook output priority 0; policy accept;
  meta mark {KILLSWITCH_MARK:#x} counter accept
  meta mark {network.BROKER_MARK:#x} meta priority {network.PROXY_PRIORITY} counter accept
  meta mark {network.BROKER_MARK:#x} counter drop
 }}
}}
"""
    subprocess.run(["nft", "-f", "-"], input=policy.encode(), check=True)
    try:
        run_case(library, proxy=True)
        run_case(library, proxy=False)
        subprocess.run(["nft", "list", "table", "inet", "incy_test"], check=True)
    finally:
        subprocess.run(["nft", "delete", "table", "inet", "incy_test"], check=True)


if __name__ == "__main__":
    main()
