"""Private worker/broker socket-FD channel; no commands, paths or configuration cross it."""

from __future__ import annotations

import array
import errno
import os
import socket
import threading
from collections.abc import Callable

TIMEOUT = 3.0


class Client:
    def __init__(self, channel: socket.socket) -> None:
        self._channel = channel
        self._channel.settimeout(TIMEOUT)
        self._lock = threading.Lock()
        self._failed = False

    def protect(self, fd: int) -> bool:
        # Core may call from several native threads; replies must stay paired with requests.
        with self._lock:
            if self._failed:
                return False
            try:
                if socket.send_fds(self._channel, [b"P"], [fd]) != 1:
                    raise OSError("Incomplete INCY broker request")
                reply = self._channel.recv(2)
                if reply not in (b"0", b"1"):
                    raise OSError("Invalid INCY broker response")
                return reply == b"1"
            except OSError:
                # A late reply after a timeout must never authorize a subsequent socket.
                self._failed = True
                self._channel.close()
                return False


def _protect(fd: int, apply: Callable[[socket.socket], None]) -> None:
    sock = socket.socket(fileno=fd)
    try:
        if sock.family not in (socket.AF_INET, socket.AF_INET6) or sock.type not in (
            socket.SOCK_STREAM,
            socket.SOCK_DGRAM,
        ):
            raise ValueError("Not an outbound IP socket")
        if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN):
            raise ValueError("Listening socket")
        try:
            sock.getpeername()
        except OSError as error:
            if error.errno != errno.ENOTCONN:
                raise
        else:
            raise ValueError("Already connected socket")
        apply(sock)
    finally:
        sock.detach()  # The request handler owns and closes the received descriptor.


def serve(channel: socket.socket, apply: Callable[[socket.socket], None]) -> None:
    """Serve an already-private SOCK_SEQPACKET channel, with a fixed socket operation."""
    while True:
        try:
            # socket.recv_fds currently ignores its flags argument, including MSG_CMSG_CLOEXEC.
            request, ancillary, flags, _ = channel.recvmsg(
                2, socket.CMSG_SPACE(4 * array.array("i").itemsize), socket.MSG_CMSG_CLOEXEC
            )
        except OSError:
            return
        fds = array.array("i")
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds.frombytes(data[: len(data) - len(data) % fds.itemsize])
        accepted = False
        try:
            if not request:
                return
            if (
                request == b"P"
                and len(fds) == 1
                and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            ):
                try:
                    _protect(fds[0], apply)
                    accepted = True
                except OSError, ValueError:
                    pass
        finally:
            for fd in fds:
                os.close(fd)
        try:
            channel.send(b"1" if accepted else b"0")
        except OSError:
            return
