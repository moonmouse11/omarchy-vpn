"""Fixed root-side INCY session. Install only in a root-owned, isolated Python package."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import signal
import socket
import stat
import struct
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path

from incy.broker import serve
from incy.network import protect_socket

IFACE = "incy-xray"
LOCK = Path("/run/omarchy-vpn-incy.lock")
IP = "/usr/bin/ip"


def caller_uid() -> int:
    raw = os.environ.get("SUDO_UID", "")
    if os.geteuid() != 0 or re.fullmatch(r"[0-9]+", raw) is None:
        raise PermissionError("INCY network helper requires sudo caller identity")
    uid = int(raw)
    if not 0 < uid < 2**32 - 1:
        raise PermissionError("Invalid INCY caller uid")
    return uid


def endpoint(uid: int, token: str) -> Path:
    if not 0 < uid < 2**32 - 1 or re.fullmatch(r"[0-9a-f]{32}", token) is None:
        raise ValueError("Invalid INCY session identity")
    return Path(f"/run/user/{uid}/omarchy-vpn/incy-{token}.sock")


def _ip(*args: str) -> str:
    result = subprocess.run(
        [IP, *args],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    if result.returncode:
        raise OSError(f"INCY network setup: {result.stderr.strip()}")
    return result.stdout


def uplink_interface() -> str:
    links = json.loads(_ip("-json", "-details", "link", "show"))
    excluded = {
        link["ifname"]
        for link in links
        if link.get("linkinfo", {}).get("info_kind") in ("tun", "wireguard", "amneziawg")
    }
    routes = sorted(
        json.loads(_ip("-json", "route", "show", "default")),
        key=lambda route: route.get("metric", 0),
    )
    for route in routes:
        iface = route.get("dev", "")
        if iface and iface not in excluded and iface != "lo":
            return str(iface)
    raise OSError("No INCY uplink route")


@contextmanager
def _switch_lock() -> Iterator[None]:
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError("Unsafe INCY lock file")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def _interface_exists() -> bool:
    try:
        socket.if_nametoindex(IFACE)
    except OSError:
        return False
    return True


def _new_tun() -> int:
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        fcntl.ioctl(fd, 0x400454CA, struct.pack("16sH", IFACE.encode(), 0x9001))
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def tunnel() -> Iterator[int]:
    with _switch_lock():
        if _interface_exists():
            raise FileExistsError("INCY interface is already owned")
        fd = _new_tun()
        try:
            _ip("address", "add", "172.19.0.2/30", "dev", IFACE)
            _ip("link", "set", "dev", IFACE, "mtu", "1500", "up")
            _ip("route", "add", "0.0.0.0/1", "dev", IFACE)
            _ip("route", "add", "128.0.0.0/1", "dev", IFACE)
            yield fd
        finally:
            try:
                _ip("link", "delete", "dev", IFACE)
            finally:
                os.close(fd)


def require_peer_uid(channel: socket.socket, uid: int) -> None:
    _, peer_uid, _ = struct.unpack(
        "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    )
    if peer_uid != uid:
        raise PermissionError("INCY session peer uid does not match sudo caller")


def run_session(channel: socket.socket, mode: str, uid: int, uplink: str) -> None:
    if mode not in ("connect", "probe"):
        raise ValueError("Invalid INCY session mode")
    if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET:
        raise ValueError("Invalid INCY session channel")
    require_peer_uid(channel, uid)
    if mode == "connect":
        with tunnel() as fd:
            if socket.send_fds(channel, [b"T"], [fd]) != 1:
                raise OSError("Could not transfer INCY TUN descriptor")
            serve(channel, lambda sock: protect_socket(sock, uplink))
    else:
        channel.sendall(b"N")
        serve(channel, lambda sock: protect_socket(sock, uplink))


@contextmanager
def shutdown_on_signal(channel: socket.socket) -> Iterator[None]:
    def stop(_signum: int, _frame: object) -> None:
        with suppress(OSError):
            channel.shutdown(socket.SHUT_RDWR)

    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        for sig in previous:
            signal.signal(sig, stop)
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fixed INCY network helper")
    parser.add_argument("mode", choices=("connect", "probe"))
    parser.add_argument("token")
    args = parser.parse_args(argv)
    try:
        uid = caller_uid()
        address = endpoint(uid, args.token)
        with (
            socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel,
            shutdown_on_signal(channel),
        ):
            channel.settimeout(5)
            channel.connect(str(address))
            # Authenticate before probing or changing any host network state.
            require_peer_uid(channel, uid)
            uplink = uplink_interface()
            channel.settimeout(None)
            run_session(channel, args.mode, uid, uplink)
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"INCY network helper: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
