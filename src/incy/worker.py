"""Unprivileged INCY library boundary; never load bundled code before checking privileges."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import select
import signal
import socket
import struct
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

from incy import broker
from incy.network import prepare_config

CONFIG_MAX = 16 * 1024 * 1024
STATUS = Path("/proc/self/status")
PROTECT_CALLBACK = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_long)


def require_unprivileged() -> None:
    if os.getuid() == 0 or os.geteuid() == 0 or 0 in os.getresuid():
        raise PermissionError("INCY core must not run as root")
    fields = dict(line.split(":", 1) for line in STATUS.read_text().splitlines() if ":" in line)
    for name in ("CapPrm", "CapEff", "CapAmb"):
        try:
            value = int(fields[name], 16)
        except KeyError, ValueError:
            raise PermissionError("Cannot verify INCY core capabilities") from None
        if value:
            raise PermissionError("INCY core must not have capabilities")


class Core:
    def __init__(self, library: str) -> None:
        require_unprivileged()
        self._lib = ctypes.CDLL(library)
        self._lib.IncycoreXrayStart.argtypes = [ctypes.c_char_p]
        self._lib.IncycoreStartXrayWithTunFd.argtypes = [ctypes.c_char_p, ctypes.c_int]
        self._lib.IncycoreXrayStop.argtypes = []
        for function in (
            self._lib.IncycoreXrayStart,
            self._lib.IncycoreStartXrayWithTunFd,
            self._lib.IncycoreXrayStop,
        ):
            function.restype = ctypes.c_void_p
        self._lib.IncycoreFreeString.argtypes = [ctypes.c_void_p]
        self._lib.IncycoreFreeString.restype = None
        self._lib.IncycoreXrayIsRunning.argtypes = []
        self._lib.IncycoreXrayIsRunning.restype = ctypes.c_int
        self._protector: Callable[[int], bool] | None = None

    def _check(self, error: int | None) -> None:
        if error is not None:
            try:
                message = ctypes.string_at(error).decode("utf-8", errors="replace")
            finally:
                self._lib.IncycoreFreeString(error)
            raise OSError(message)

    def set_assets(self, path: str) -> None:
        self._lib.IncycoreSetAssetsPath.argtypes = [ctypes.c_char_p]
        self._lib.IncycoreSetAssetsPath.restype = None
        self._lib.IncycoreSetAssetsPath(path.encode())

    def start(self, config: dict, *, tun_fd: int | None = None) -> None:
        """Start core; a successful TUN start transfers ownership of tun_fd to native code."""
        if tun_fd is not None and tun_fd < 3:
            raise ValueError("TUN fd must be >= 3")
        payload = json.dumps(config, separators=(",", ":"), ensure_ascii=False).encode()
        if tun_fd is None:
            self._check(self._lib.IncycoreXrayStart(payload))
        else:
            self._check(self._lib.IncycoreStartXrayWithTunFd(payload, tun_fd))

    def set_socket_protector(self, protect: Callable[[int], bool]) -> None:
        if self.running():
            raise RuntimeError("Install the socket protector before starting INCY")

        def checked(fd: int) -> bool:
            try:
                return bool(protect(fd))
            except BaseException:  # noqa: BLE001 — no exception may escape a native callback
                # Exceptions escaping a ctypes callback leave its native return value undefined.
                return False

        callback = PROTECT_CALLBACK(checked)
        self._lib.xray_set_protect.argtypes = [PROTECT_CALLBACK]
        self._lib.xray_set_protect.restype = None
        # The Go IncycoreSetProtectFd wrapper discards the callback's failure result.
        self._lib.xray_set_protect(callback)
        self._protector = callback

    def stop(self) -> None:
        self._check(self._lib.IncycoreXrayStop())
        if self._protector is not None:
            self._lib.xray_set_protect(PROTECT_CALLBACK())
            self._protector = None

    def running(self) -> bool:
        return bool(self._lib.IncycoreXrayIsRunning())


def read_config(stream: BinaryIO) -> dict:
    raw = stream.read(CONFIG_MAX + 1)
    if len(raw) > CONFIG_MAX:
        raise ValueError("INCY config is too large")
    config = json.loads(raw)
    if not isinstance(config, dict):
        raise ValueError("INCY config must be a JSON object")
    return config


def serve(
    core: Core,
    config: dict,
    tun_fd: int | None,
    wait: Callable[[], bool],
    ready: Callable[[], None] | None = None,
) -> None:
    try:
        core.start(config, tun_fd=tun_fd)
        if ready is not None:
            ready()
        while core.running():
            if wait():
                break
    finally:
        core.stop()


def broker_lost(channel: socket.socket) -> bool:
    if channel.fileno() < 0:
        return True
    poll = select.poll()
    poll.register(channel, select.POLLHUP | select.POLLERR | select.POLLRDHUP)
    return bool(poll.poll(0))


def notify_ready(fd: int, message: dict) -> None:
    try:
        os.write(fd, json.dumps(message, ensure_ascii=False).encode(errors="replace"))
    finally:
        os.close(fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Unprivileged INCY core worker")
    parser.add_argument("--library", required=True)
    parser.add_argument("--tun-fd", type=int)
    parser.add_argument("--broker-fd", type=int)
    parser.add_argument("--ready-fd", type=int)
    parser.add_argument("--assets")
    args = parser.parse_args(argv)
    ready_fd = args.ready_fd

    def ready() -> None:
        nonlocal ready_fd
        if ready_fd is not None:
            fd, ready_fd = ready_fd, None
            notify_ready(fd, {"ready": True})

    stopped = threading.Event()
    signals = (signal.SIGTERM, signal.SIGINT)
    previous = {sig: signal.getsignal(sig) for sig in signals}
    channel: socket.socket | None = None
    try:
        for sig in signals:
            signal.signal(sig, lambda _sig, _frame: stopped.set())
        if args.broker_fd is not None:
            if args.broker_fd < 3:
                raise ValueError("Broker fd must be >= 3")
            channel = socket.socket(fileno=args.broker_fd)
            if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET:
                raise ValueError("Invalid INCY broker channel")
            _, uid, _ = struct.unpack(
                "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if uid != 0:
                raise PermissionError("INCY broker must run as root")
        config = prepare_config(read_config(sys.stdin.buffer))
        core = Core(args.library)
        if args.assets:
            core.set_assets(args.assets)
        if channel is not None:
            core.set_socket_protector(broker.Client(channel).protect)
        serve(
            core,
            config,
            args.tun_fd,
            lambda: stopped.wait(0.25) or (channel is not None and broker_lost(channel)),
            ready,
        )
        return 0
    except (OSError, ValueError) as error:
        if ready_fd is not None:
            fd, ready_fd = ready_fd, None
            notify_ready(fd, {"error": str(error)[:500]})
        print(f"INCY worker: {error}", file=sys.stderr)
        return 1
    finally:
        if channel is not None:
            channel.close()
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    sys.exit(main())
