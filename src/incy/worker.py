"""Unprivileged INCY library boundary; never load bundled code before checking privileges."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import signal
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

CONFIG_MAX = 16 * 1024 * 1024
STATUS = Path("/proc/self/status")


def require_unprivileged() -> None:
    if os.getuid() == 0 or os.geteuid() == 0:
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

    def _check(self, error: int | None) -> None:
        if error is not None:
            try:
                message = ctypes.string_at(error).decode("utf-8", errors="replace")
            finally:
                self._lib.IncycoreFreeString(error)
            raise OSError(message)

    def start(self, config: dict, *, tun_fd: int | None = None) -> None:
        if tun_fd is not None and tun_fd < 3:
            raise ValueError("TUN fd must be >= 3")
        payload = json.dumps(config, separators=(",", ":"), ensure_ascii=False).encode()
        if tun_fd is None:
            self._check(self._lib.IncycoreXrayStart(payload))
        else:
            self._check(self._lib.IncycoreStartXrayWithTunFd(payload, tun_fd))

    def stop(self) -> None:
        self._check(self._lib.IncycoreXrayStop())

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


def serve(core: Core, config: dict, tun_fd: int | None, wait: Callable[[], bool]) -> None:
    try:
        core.start(config, tun_fd=tun_fd)
        while core.running():
            if wait():
                break
    finally:
        core.stop()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Unprivileged INCY core worker")
    parser.add_argument("--library", required=True)
    parser.add_argument("--tun-fd", type=int)
    args = parser.parse_args(argv)
    stopped = threading.Event()
    signals = (signal.SIGTERM, signal.SIGINT)
    previous = {sig: signal.getsignal(sig) for sig in signals}
    try:
        for sig in signals:
            signal.signal(sig, lambda _sig, _frame: stopped.set())
        config = read_config(sys.stdin.buffer)
        core = Core(args.library)
        serve(core, config, args.tun_fd, lambda: stopped.wait(0.25))
        return 0
    except (OSError, ValueError) as error:
        print(f"INCY worker: {error}", file=sys.stderr)
        return 1
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    sys.exit(main())
