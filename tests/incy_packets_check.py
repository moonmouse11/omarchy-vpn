"""Real TUN, uplink, Shadowsocks, DNS and happ-ks in two disposable network namespaces."""

from __future__ import annotations

import copy
import ctypes
import http.client
import http.server
import json
import os
import select
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

from incy.config import build_incy_runtime_config
from incy.worker import Core

ENTRY = "11.0.0.2"
TARGET = "11.0.0.1"
DNS = "11.0.0.53"
PASSWORD = "12345678-1234-1234-1234-123456789abc"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(self.client_address[0].encode())

    def log_message(self, *_args):
        pass


class HTTP6(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6


def _dns_server(sock: socket.socket, events: int) -> None:
    while True:
        data, address = sock.recvfrom(4096)
        bootstrap = data[12:].startswith(b"\x05entry\x07example\0")
        os.write(events, (("bootstrap:" if bootstrap else "app:") + address[0] + "\n").encode())
        reply = data[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + data[12:]
        reply += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
        sock.sendto(reply + socket.inet_aton(ENTRY if bootstrap else TARGET), address)


def _peer(go: int, events: int, ip) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.unshare.argtypes = [ctypes.c_int]
    libc.unshare.restype = ctypes.c_int
    if libc.unshare(0x40000000) != 0:  # CLONE_NEWNET
        raise OSError(ctypes.get_errno(), "Cannot create isolated test peer netns")
    os.write(events, b"N")
    assert os.read(go, 1) == b"G"
    ip("link", "set", "lo", "up")
    ip("link", "set", "peer", "up")
    ip("address", "add", "198.51.100.1/24", "dev", "peer")
    for address in (ENTRY, TARGET, DNS):
        ip("address", "add", address + "/32", "dev", "lo")
    ip("-6", "address", "add", "2001:db8::1/64", "dev", "peer", "nodad")
    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns.bind((DNS, 53))
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    server_config = {
        "log": {"loglevel": "debug", "access": "/tmp/peer-access", "error": "/tmp/peer-error"},
        "inbounds": [
            {
                "listen": ENTRY,
                "port": 8388,
                "protocol": "vless",
                "settings": {"decryption": "none", "clients": [{"id": PASSWORD}]},
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "certificates": [
                            {
                                "certificateFile": "/tmp/incy-cert.pem",
                                "keyFile": "/tmp/incy-key.pem",
                            }
                        ]
                    },
                },
            }
        ],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        "routing": {"rules": [{"network": "tcp,udp", "outboundTag": "direct"}]},
    }
    server_config["inbounds"].append(
        {
            "listen": ENTRY,
            "port": 8389,
            "protocol": "shadowsocks",
            "settings": {
                "method": "aes-128-gcm",
                "password": "legacy-ss-test",
                "network": "tcp,udp",
            },
        }
    )
    server = subprocess.Popen(
        [
            "/usr/local/bin/python3",
            "-c",
            "import os,sys; from incy.launcher import watch_parent; "
            "watch_parent(int(sys.argv[1])); "
            "os.execv('/opt/xray/26.9.30/xray', ['xray','run','-config','stdin:'])",
            str(os.getpid()),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        env={**os.environ, "PYTHONPATH": "/repo/src"},
    )
    assert server.stdin is not None
    server.stdin.write(json.dumps(server_config).encode())
    server.stdin.close()
    deadline = time.monotonic() + 5
    while True:
        try:
            with socket.create_connection((ENTRY, 8389), timeout=0.2):
                break
        except OSError:
            assert server.poll() is None and time.monotonic() < deadline
            time.sleep(0.05)
    for server in (
        http.server.ThreadingHTTPServer(("0.0.0.0", 18080), Handler),
        HTTP6(("2001:db8::1", 18080), Handler),
    ):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    https = http.server.ThreadingHTTPServer((TARGET, 18443), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain("/tmp/incy-cert.pem", "/tmp/incy-key.pem")
    https.socket = tls.wrap_socket(https.socket, server_side=True)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    threading.Thread(target=_dns_server, args=(dns, events), daemon=True).start()
    baseline = Core("/inspect/lib/app/resources/bin/libincycore.so")
    baseline.start(
        {
            "inbounds": [{"listen": "127.0.0.1", "port": 18090, "protocol": "http"}],
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
                                "password": "legacy-ss-test",
                            }
                        ]
                    },
                }
            ],
            "routing": {"rules": [{"network": "tcp,udp", "outboundTag": "proxy"}]},
        }
    )
    connection = http.client.HTTPConnection("127.0.0.1", 18090, timeout=3)
    try:
        connection.set_tunnel(TARGET, 18080)
        connection.request("GET", "/")
        response = connection.getresponse()
        print(
            "Standalone native SS baseline (no TUN, no broker):",
            response.status,
            response.read(),
            flush=True,
        )
    except OSError as exc:
        print("Standalone native SS baseline (no TUN, no broker) failed:", exc, flush=True)
    finally:
        connection.close()
        baseline.stop()
    os.write(events, b"R")
    threading.Event().wait()


def http_source(host: str = TARGET, padding: int = 0, domain: str = "") -> str:
    conn = http.client.HTTPConnection(host, 18080, timeout=5)
    try:
        headers = {"X-Pad": "x" * padding}
        if domain:
            headers["Host"] = domain
        conn.request("GET", "/", headers=headers)
        return conn.getresponse().read().decode()
    finally:
        conn.close()


def https_source() -> str:
    context = ssl.create_default_context(cafile="/tmp/incy-cert.pem")
    with (
        socket.create_connection((TARGET, 18443), timeout=5) as sock,
        context.wrap_socket(sock, server_hostname="incy-test") as tls,
    ):
        tls.sendall(b"GET / HTTP/1.0\r\nHost: incy-test\r\n\r\n")
        response = http.client.HTTPResponse(tls)
        response.begin()
        assert response.status == 200
        return response.read().decode()


def _dns_query(events: int) -> None:
    query = struct.pack("!6H", 7, 0x100, 1, 0, 0, 0) + b"\x04test\x07example\0\0\x01\0\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(query, ("8.8.8.8", 53))
        reply, _ = sock.recvfrom(4096)
    assert socket.inet_aton(TARGET) in reply
    assert select.select([events], [], [], 5)[0], "DNS did not reach the peer resolver"
    sources = os.read(events, 4096).decode().splitlines()
    assert "bootstrap:198.51.100.2" in sources, sources
    app_sources = [source for source in sources if source.startswith("app:")]
    assert app_sources and "app:198.51.100.2" not in app_sources, sources


def packet_checks(start, stop, ip, env: dict) -> None:
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "/tmp/incy-key.pem",
            "-out",
            "/tmp/incy-cert.pem",
            "-days",
            "1",
            "-subj",
            "/CN=incy-test",
            "-addext",
            "subjectAltName=DNS:incy-test,IP:11.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "extendedKeyUsage=serverAuth",
        ],
        user=65534,
        group=65534,
        extra_groups=[],
        check=True,
        capture_output=True,
        timeout=10,
    )
    events_read, events_write = os.pipe()
    go_read, go_write = os.pipe()
    peer = os.fork()
    if peer == 0:
        os.close(events_read)
        os.close(go_write)
        try:
            _peer(go_read, events_write, ip)
        except BaseException:  # noqa: BLE001 — fork child logs failures before os._exit
            traceback.print_exc()
        finally:
            os._exit(1)
    os.close(go_read)
    os.close(events_write)
    try:
        assert os.read(events_read, 1) == b"N"
        ip("link", "delete", "uplink")
        ip("link", "add", "uplink", "type", "veth", "peer", "name", "peer")
        ip("link", "set", "peer", "netns", str(peer))
        ip("link", "set", "uplink", "up")
        ip("address", "add", "198.51.100.2/24", "dev", "uplink")
        ip("-6", "address", "add", "2001:db8::2/64", "dev", "uplink", "nodad")
        ip("route", "add", "default", "via", "198.51.100.1")
        os.write(go_write, b"G")
        assert os.read(events_read, 1) == b"R"
        assert http_source() == "198.51.100.2", "physical path baseline did not work"
        assert http_source("2001:db8::1") == "2001:db8::2"
        config = build_incy_runtime_config(
            {
                "remarks": "isolated test",
                "dns": {"servers": [DNS], "queryStrategy": "UseIPv4"},
                "outbounds": [
                    {
                        "protocol": "vless",
                        "tag": "proxy",
                        "settings": {
                            "vnext": [
                                {
                                    "address": "entry.example",
                                    "port": 8388,
                                    "users": [{"id": PASSWORD, "encryption": "none"}],
                                }
                            ]
                        },
                        "streamSettings": {
                            "network": "tcp",
                            "security": "tls",
                            "tlsSettings": {
                                "serverName": "incy-test",
                                "certificates": [
                                    {"certificateFile": "/tmp/incy-cert.pem", "usage": "verify"}
                                ],
                            },
                        },
                    },
                    {"protocol": "freedom", "tag": "direct"},
                ],
            },
            tunnel_dns=True,
        )
        config["log"] = {
            "loglevel": "debug",
            "access": "/tmp/incy-access",
            "error": "/tmp/incy-error",
        }
        config["routing"]["rules"].append(
            {
                "domain": ["geosite:category-ads-all"],
                "outboundTag": "direct",
            }
        )
        subprocess.run(
            [
                "bash",
                "/repo/scripts/happ-killswitch",
                "on",
                "192.0.2.99",
                "--no-conf",
                "--iface",
                "incy-xray",
            ],
            check=True,
            timeout=5,
        )
        proc = start("connect", config)
        try:
            try:
                assert http_source() == TARGET, "TUN traffic did not exit through the proxy"
            except BaseException:
                for log in (
                    "/tmp/incy-access",
                    "/tmp/incy-error",
                    "/tmp/peer-access",
                    "/tmp/peer-error",
                ):
                    if Path(log).exists():
                        print(Path(log).read_text(), flush=True)
                subprocess.run(["nft", "list", "ruleset"], check=True)
                subprocess.run(["ip", "route", "get", ENTRY, "oif", "uplink"], check=True)
                subprocess.run(["ss", "-tn"], check=True)
                raise
            _dns_query(events_read)
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import json,sys; from delayping import incy_probe; "
                    "delay=incy_probe(json.load(sys.stdin), 'https://"
                    + TARGET
                    + ":18443/', None); "
                    "assert delay is not None and delay > 0; print('Real Ping on live tunnel: OK')",
                ],
                input=json.dumps(config),
                text=True,
                user=65534,
                group=65534,
                extra_groups=[],
                env={**env, "SSL_CERT_FILE": "/tmp/incy-cert.pem"},
                check=True,
                timeout=20,
            )
            assert proc.poll() is None and Path("/sys/class/net/incy-xray").exists()
            try:
                http_source("2001:db8::1")
            except OSError:
                pass
            else:
                raise AssertionError("IPv6 escaped the real kill switch")
            print(
                "Real TUN -> protected uplink -> VLESS/TLS -> HTTP/DNS, IPv6 blocked: OK",
                flush=True,
            )
        finally:
            stop(proc)
        ss_config = copy.deepcopy(config)
        outbound = next(o for o in ss_config["outbounds"] if o.get("tag") == "proxy")
        mark = outbound["streamSettings"]["sockopt"]["mark"]
        outbound.update(
            protocol="shadowsocks",
            settings={
                "servers": [
                    {
                        "address": "entry.example",
                        "port": 8389,
                        "method": "aes-128-gcm",
                        "password": "legacy-ss-test",
                    }
                ]
            },
            streamSettings={"sockopt": {"mark": mark}},
        )
        ss_proc = start("connect", ss_config)
        try:
            assert https_source() == TARGET, "Shadowsocks HTTPS did not reach its exit"
            print("Real Shadowsocks HTTPS: OK", flush=True)
            assert http_source(domain="test.example") == TARGET, (
                "Shadowsocks TUN traffic did not reach its exit"
            )
            print("Real Shadowsocks TUN transport: OK", flush=True)
        finally:
            stop(ss_proc)
        config["routing"]["rules"].insert(0, {"ip": [TARGET], "outboundTag": "direct"})
        direct = next(o for o in config["outbounds"] if o.get("tag") == "direct")
        direct.setdefault("streamSettings", {})["sockopt"] = {
            "customSockopt": [{"level": "1", "opt": "12", "value": "6", "type": "int"}]
        }
        proc = start("connect", config)
        try:
            try:
                http_source()
            except OSError:
                pass
            else:
                raise AssertionError("Subscription direct escaped the real kill switch")
            subprocess.run(
                ["bash", "/repo/scripts/happ-killswitch", "off"],
                check=True,
                capture_output=True,
                timeout=5,
            )
            assert http_source() == "198.51.100.2", "direct failed with kill switch off"
            print(
                "Real happ-ks blocks direct despite requested priority 6; off restores it: OK",
                flush=True,
            )
        finally:
            stop(proc)
    finally:
        os.close(go_write)
        os.close(events_read)
        os.kill(peer, signal.SIGKILL)
        os.waitpid(peer, 0)
