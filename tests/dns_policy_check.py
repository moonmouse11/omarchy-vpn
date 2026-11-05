"""Opt-in real kernel DNS/nft checks; run only through make test-dns-docker."""

from __future__ import annotations

import os
import select
import signal
import socket
import struct
import subprocess
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vpn_dns.control import DNS_MARK, dns_socket
from vpn_dns.wire import query

DNS = "198.51.100.53"
OTHER = "198.51.100.54"
ANSWER = "203.0.113.77"
SCRIPT = Path("/repo/scripts/happ-killswitch")


def run(*args: str) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=10).stdout


def exact(sock: socket.socket, size: int) -> bytes:
    result = b""
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise OSError("short TCP request")
        result += chunk
    return result


def response(packet: bytes, tcp: bool) -> bytes:
    truncated = b"\x03tcp" in packet and not tcp
    header = packet[:2] + struct.pack(
        "!5H", 0x8380 if truncated else 0x8180, 1, 0 if truncated else 1, 0, 0
    )
    answer = (
        b""
        if truncated
        else b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04" + socket.inet_aton(ANSWER)
    )
    return header + packet[12:] + answer


def serve(channel: socket.socket) -> None:
    os.unshare(os.CLONE_NEWNET)
    channel.send(b"N")
    assert channel.recv(1) == b"I"
    run("ip", "link", "set", "lo", "up")
    run("ip", "addr", "add", "192.0.2.2/24", "dev", "dns-peer")
    for address in (DNS, OTHER):
        run("ip", "addr", "add", address + "/32", "dev", "dns-peer")
    run("ip", "link", "set", "dns-peer", "up")
    listeners = []
    for address in (DNS, OTHER):
        for port in (53, 54, 853):
            for tcp in (False, True):
                sock = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
                )
                sock.bind((address, port))
                if tcp:
                    sock.listen()
                listeners.append(sock)
    channel.send(b"R")
    while True:
        for sock in select.select(listeners, [], [], 1)[0]:
            if sock.type == socket.SOCK_DGRAM:
                packet, peer = sock.recvfrom(2048)
                if b"\x04hang" in packet:
                    channel.send(b"H")
                    continue
                sock.sendto(response(packet, False), peer)
            else:
                conn, _ = sock.accept()
                with conn:
                    conn.settimeout(1)
                    try:
                        packet = exact(conn, struct.unpack("!H", exact(conn, 2))[0])
                        reply = response(packet, True)
                        conn.sendall(struct.pack("!H", len(reply)) + reply)
                    except OSError:
                        pass


def exchange(address: str, port: int, tcp: bool, mark: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"dns-up\0")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
        sock.settimeout(0.4)
        try:
            sock.connect((address, port))
            packet = query("vpn.example", 23)
            sock.sendall((struct.pack("!H", len(packet)) if tcp else b"") + packet)
            reply = exact(sock, struct.unpack("!H", exact(sock, 2))[0]) if tcp else sock.recv(2048)
            return reply == response(packet, tcp)
        except OSError:
            return False


def rules(bootstrap: bool) -> None:
    args = ["bash", str(SCRIPT), "rules", "--no-conf"]
    if bootstrap:
        args += ["--dns", DNS]
    text = run(*args)
    subprocess.run(["nft", "-f", "-"], input=text, text=True, check=True, timeout=5)


def client(hanging: bool = False) -> None:
    from vpn_dns.bootstrap import resolve

    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    if hanging:

        class Cancelled(BaseException):
            pass

        def cancel(*args):
            raise Cancelled

        signal.signal(signal.SIGTERM, cancel)
        try:
            resolve([f"n{i}.hang.vpn.example" for i in range(32)], timeout=4)
        except Cancelled:
            return
        raise AssertionError("lookup finished without cancellation")
    answers = resolve(["vpn.example", "tcp.vpn.example"], timeout=4)
    assert answers == {"vpn.example": ANSWER, "tcp.vpn.example": ANSWER}, answers


def spawn_client(hanging: bool = False) -> int:
    pid = os.fork()
    if pid == 0:
        try:
            client(hanging)
        except BaseException:  # noqa: BLE001 — a fork child must not run the parent's cleanup
            traceback.print_exc()
            os._exit(1)
        os._exit(0)
    return pid


def main() -> None:
    assert Path("/.dockerenv").exists(), "Disposable Docker container required"
    assert os.getuid() == 0
    root, child = socket.socketpair()
    pid = os.fork()
    if pid == 0:
        root.close()
        serve(child)
        os._exit(0)
    child.close()
    try:
        root.settimeout(5)
        assert root.recv(1) == b"N"
        run("ip", "link", "add", "dns-up", "type", "veth", "peer", "name", "dns-peer")
        run("ip", "link", "set", "dns-peer", "netns", str(pid))
        run("ip", "addr", "add", "192.0.2.1/24", "dev", "dns-up")
        run("ip", "link", "set", "dns-up", "up")
        run("ip", "route", "add", "default", "dev", "dns-up", "metric", "50")
        root.send(b"I")
        assert root.recv(1) == b"R"
        # Negative control: all destinations/ports really answer before nft filters.
        for tcp in (False, True):
            for address, port in ((DNS, 53), (DNS, 54), (DNS, 853), (OTHER, 53)):
                assert exchange(address, port, tcp, 0), (address, port, tcp, "control")
        run("ip", "tuntap", "add", "dev", "happ-dead", "mode", "tun")
        run("ip", "link", "set", "happ-dead", "up")
        run("ip", "route", "add", "default", "dev", "happ-dead", "metric", "1")
        rules(True)
        for tcp in (False, True):
            assert not exchange(DNS, 53, tcp, 0), "ordinary DNS escaped"
            assert not exchange(DNS, 53, tcp, 0x42), "wrong mark escaped"
            assert not exchange(DNS, 853, tcp, DNS_MARK), "DoT port allowance survived"
            assert exchange(DNS, 53, tcp, DNS_MARK), "marked DNS blocked by dead default tunnel"
            assert not exchange(DNS, 54, tcp, DNS_MARK), "mark allowed wrong port"
            assert not exchange(OTHER, 53, tcp, DNS_MARK), "mark allowed wrong resolver"
        assert f"nameserver {DNS}" in Path("/etc/resolv.conf").read_text()
        runtime = Path("/run/user/65534")
        runtime.mkdir(parents=True)
        runtime.chmod(0o700)
        os.chown(runtime, 65534, 65534)
        caller = spawn_client()
        assert os.waitpid(caller, 0)[1] == 0, "authenticated helper/client lookup failed"
        assert not list(runtime.glob("omarchy-vpn/dns-*.sock")), "session listener leaked"
        caller = spawn_client(hanging=True)
        assert root.recv(1) == b"H", "cancel test did not reach a real DNS query"
        os.kill(caller, signal.SIGTERM)
        deadline = time.monotonic() + 2
        while True:
            done, status = os.waitpid(caller, os.WNOHANG)
            if done:
                assert status == 0, "cancelled client failed cleanup"
                break
            if time.monotonic() >= deadline:
                os.kill(caller, signal.SIGKILL)
                os.waitpid(caller, 0)
                raise AssertionError("cancellation exceeded switch preemption grace")
            time.sleep(0.01)
        assert not list(runtime.glob("omarchy-vpn/dns-*.sock")), "cancel left a listener"
        with dns_socket(DNS, False, "dns-up", 65534, 65534) as leased:
            leased.settimeout(0.4)
            packet = query("vpn.example", 31)
            leased.sendall(packet)
            assert leased.recv(2048) == response(packet, False)
            rules(False)
            try:
                leased.sendall(packet)
                leased.recv(2048)
            except PermissionError, TimeoutError:
                pass
            else:
                raise AssertionError("existing DNS socket survived scope removal")
        for tcp in (False, True):
            assert not exchange(DNS, 53, tcp, DNS_MARK), "bootstrap permission survived cleanup"
        print(
            "PASS: controls; unmarked DNS denied; marked UDP/TCP only configured :53; "
            "dead tunnel; real authenticated client/TCP fallback; "
            "cancellation within grace; cleanup"
        )
    finally:
        root.close()
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)


if __name__ == "__main__":
    main()
