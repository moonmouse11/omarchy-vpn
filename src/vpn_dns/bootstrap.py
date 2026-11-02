"""Endpoint-only resolver using fixed privileged DNS sockets, never libc DNS."""

from __future__ import annotations

import array
import concurrent
import contextlib
import ipaddress
import json
import os
import secrets
import socket
import stat
import struct
import subprocess
import threading
import time
from collections.abc import Iterator
from typing import TYPE_CHECKING

import lazyimports  # noqa: F401 — registers concurrent.futures lazily
from incy.privileged import require_peer_uid
from incy.worker import require_unprivileged
from vpn_dns import wire as dnswire
from vpn_dns.control import endpoint

if TYPE_CHECKING:
    import concurrent.futures

HELPER = "/usr/local/bin/omarchy-vpn-helper"


class SocketRefused(OSError):
    """A complete broker refusal, unlike a timed-out or malformed reply."""


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Endpoint DNS deadline exceeded")
    return remaining


def _receive(channel: socket.socket, size: int, expected_fds: int) -> tuple[bytes, int | None]:
    fds = array.array("i")
    try:
        data, ancillary, flags, _ = channel.recvmsg(
            size, socket.CMSG_SPACE(2 * fds.itemsize), socket.MSG_CMSG_CLOEXEC
        )
        for level, kind, raw in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds.frombytes(raw[: len(raw) - len(raw) % fds.itemsize])
        refused = expected_fds == 1 and data == b"E" and not fds
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or (
            len(fds) != expected_fds and not refused
        ):
            raise OSError("Invalid bootstrap DNS descriptor reply")
        return data, fds.pop() if fds else None
    finally:
        for fd in fds:
            os.close(fd)


def _exact(sock: socket.socket, size: int, deadline: float) -> bytes:
    data = bytearray()
    while len(data) < size:
        sock.settimeout(min(0.8, _remaining(deadline)))
        part = sock.recv(size - len(data))
        if not part:
            raise OSError("Bootstrap DNS TCP reply ended early")
        data.extend(part)
    return bytes(data)


class Client:
    def __init__(self, channel: socket.socket, upstreams: list[str], deadline: float):
        self.channel = channel
        self.upstreams = upstreams
        self.deadline = deadline
        self._lock = threading.Lock()

    def _socket(self, slot: int, tcp: bool) -> socket.socket:
        if not self._lock.acquire(timeout=_remaining(self.deadline)):
            raise TimeoutError("DNS bootstrap channel busy")
        try:
            self.channel.settimeout(_remaining(self.deadline))
            self.channel.sendall((b"T" if tcp else b"U") + bytes([slot]))
            data, fd = _receive(self.channel, 2, 1)
            if data == b"E" and fd is None:
                raise SocketRefused("DNS bootstrap socket unavailable")
            if fd is None:
                raise OSError("Missing bootstrap DNS socket")
            try:
                sock = socket.socket(fileno=fd)
            except BaseException:
                os.close(fd)
                raise
            try:
                expected_type = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
                if (
                    data != b"S"
                    or sock.family != socket.AF_INET
                    or sock.type != expected_type
                    or sock.getpeername() != (self.upstreams[slot], 53)
                ):
                    raise OSError("Unexpected bootstrap DNS socket")
                return sock
            except BaseException:
                sock.close()
                raise
        except SocketRefused:
            raise
        except OSError:
            self.channel.close()  # Late replies must never become a subsequent request's socket.
            raise
        finally:
            self._lock.release()

    def _exchange(self, slot: int, packet: bytes, tcp: bool) -> bytes:
        with self._socket(slot, tcp) as sock:
            sock.settimeout(min(0.8, _remaining(self.deadline)))
            sock.sendall(struct.pack("!H", len(packet)) + packet if tcp else packet)
            if not tcp:
                return sock.recv(dnswire.MAX_REPLY)
            size = struct.unpack("!H", _exact(sock, 2, self.deadline))[0]
            if size < 12:
                raise ValueError("Invalid bootstrap DNS TCP length")
            return _exact(sock, size, self.deadline)

    def query(self, host: str) -> str | None:
        identifier = secrets.randbits(16)
        packet = dnswire.query(host, identifier)
        for slot in range(len(self.upstreams)):
            try:
                _remaining(self.deadline)
                try:
                    reply = self._exchange(slot, packet, False)
                    return dnswire.answer(reply, host, identifier)
                except dnswire.Truncated:
                    return dnswire.answer(self._exchange(slot, packet, True), host, identifier)
            except OSError, ValueError:
                continue
        return None


def _accept(listener: socket.socket, proc: subprocess.Popen, deadline: float) -> socket.socket:
    while True:
        listener.settimeout(min(0.1, _remaining(deadline)))
        try:
            return listener.accept()[0]
        except TimeoutError:
            if proc.poll() is not None:
                error = proc.stderr.read(1000).decode(errors="replace") if proc.stderr else ""
                raise OSError(f"Bootstrap DNS helper failed: {error.strip()}") from None


def _upstreams(channel: socket.socket, deadline: float) -> list[str]:
    require_peer_uid(channel, 0)
    channel.settimeout(_remaining(deadline))
    data, _ = _receive(channel, 1024, 0)
    upstreams = json.loads(data)
    if not isinstance(upstreams, list) or not 0 < len(upstreams) <= 16:
        raise OSError("Invalid DNS bootstrap upstream list")
    for value in upstreams:
        if not isinstance(value, str):
            raise OSError("Invalid DNS bootstrap upstream type")
        address = ipaddress.ip_address(value)
        if (
            address.version != 4
            or address.is_loopback
            or address.is_unspecified
            or address.is_multicast
        ):
            raise OSError("Invalid DNS bootstrap upstream address")
    return upstreams


@contextlib.contextmanager
def _session(deadline: float) -> Iterator[Client]:
    require_unprivileged()
    token = secrets.token_hex(16)
    path = endpoint(os.getuid(), token)
    proc = None
    bound = False
    try:
        path.parent.mkdir(mode=0o700, exist_ok=True)
        info = path.parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PermissionError("Bootstrap DNS runtime directory must be private and user-owned")
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
            listener.bind(str(path))
            bound = True
            listener.listen(1)
            proc = subprocess.Popen(
                ["sudo", "-n", HELPER, "dns-bootstrap", token],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            with _accept(listener, proc, deadline) as channel:
                yield Client(channel, _upstreams(channel, deadline), deadline)
    finally:
        if bound:
            with contextlib.suppress(OSError):
                path.unlink()
        if proc is not None:
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=2)
            if proc.stderr:
                proc.stderr.close()


def resolve(hosts: list[str], timeout: float = 4.0) -> dict[str, str]:
    result: dict[str, str] = {}
    names = []
    for host in dict.fromkeys(hosts):
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            dnswire.canonical(host)
            names.append(host)
        else:
            if address.version == 4:
                result[host] = str(address)
    if names:
        deadline = time.monotonic() + timeout
        with (
            _session(deadline) as client,
            concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool,
        ):
            futures = {pool.submit(client.query, host): host for host in names}
            for future in concurrent.futures.as_completed(futures):
                if answer := future.result():
                    result[futures[future]] = answer
    return result
