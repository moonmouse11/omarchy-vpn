"""One unprivileged worker session; root handles only fixed TUN/socket operations."""

from __future__ import annotations

import argparse
import array
import contextlib
import ctypes
import os
import secrets
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

from incy import worker
from incy.paths import incy_library
from incy.privileged import endpoint
from incy.xray import asset_dir

HELPER = "/usr/local/bin/omarchy-vpn-helper"
START_TIMEOUT = 10.0


def receive_tun(channel: socket.socket, mode: str) -> int | None:
    fds = array.array("i")
    try:
        data, ancillary, flags, _ = channel.recvmsg(
            2,
            socket.CMSG_SPACE(2 * fds.itemsize),
            socket.MSG_CMSG_CLOEXEC,
        )
        for level, kind, raw in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds.frombytes(raw[: len(raw) - len(raw) % fds.itemsize])
        if not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            if mode == "connect" and data == b"T" and len(fds) == 1:
                return fds.pop()
            if mode == "probe" and data == b"N" and not fds:
                return None
        raise OSError("Invalid INCY network helper handshake")
    finally:
        for fd in fds:
            os.close(fd)


def watch_parent(pid: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
        raise OSError(ctypes.get_errno(), "Cannot bind INCY worker lifetime to its owner")
    if os.getppid() != pid:
        raise OSError("INCY owner exited before startup")


def run(mode: str, ready_fd: int, parent_pid: int) -> int:
    token = secrets.token_hex(16)
    path = endpoint(os.getuid(), token)
    proc: subprocess.Popen | None = None
    entered_worker = False
    try:
        helper_mode = {"connect": "connect", "probe": "probe"}.get(mode)
        if helper_mode is None:
            raise ValueError("Invalid INCY session mode")
        worker.require_unprivileged()
        watch_parent(parent_pid)
        path.parent.mkdir(mode=0o700, exist_ok=True)
        info = path.parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PermissionError("INCY runtime directory must be private and owned by this user")
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
            listener.bind(str(path))
            listener.listen(1)
            listener.settimeout(0.2)
            # run_helper() waits for exit; this broker must stay alive while we run the core.
            # Cancellation reaps this launcher in popen_xray; owner death kills it via prctl.
            # Losing its channel makes the broker remove the TUN/routes and exit.
            proc = subprocess.Popen(
                ["sudo", "-n", HELPER, "incy-network", helper_mode, token],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            deadline = time.monotonic() + START_TIMEOUT
            while True:
                try:
                    channel, _ = listener.accept()
                    break
                except TimeoutError:
                    if proc.poll() is not None:
                        error = (
                            proc.stderr.read(2000).decode(errors="replace") if proc.stderr else ""
                        )
                        raise OSError(f"INCY network helper failed: {error.strip()}") from None
                    if time.monotonic() >= deadline:
                        raise OSError("INCY network helper startup timed out") from None
            with channel:
                _, uid, _ = struct.unpack(
                    "3i",
                    channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12),
                )
                if uid != 0:
                    raise PermissionError("INCY network helper must run as root")
                channel.settimeout(START_TIMEOUT)
                tun_fd = receive_tun(channel, mode)
                channel.settimeout(None)
                args = ["--library", str(incy_library()), "--ready-fd", str(ready_fd)]
                if tun_fd is not None:
                    args += ["--tun-fd", str(tun_fd)]
                if assets := asset_dir():
                    args += ["--assets", str(assets)]
                # Native core owns a successfully started TUN fd; process exit closes failed starts.
                args += ["--broker-fd", str(channel.detach())]
                entered_worker = True
                return worker.main(args)
    except (OSError, ValueError) as exc:
        if not entered_worker:
            worker.notify_ready(ready_fd, {"error": str(exc)[:500]})
        return 1
    finally:
        path.unlink(missing_ok=True)
        if proc is not None:
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=8)
            if proc.stderr:
                proc.stderr.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("connect", "probe"))
    parser.add_argument("--ready-fd", type=int, required=True)
    parser.add_argument("--parent-pid", type=int, required=True)
    args = parser.parse_args()
    return run(args.mode, args.ready_fd, args.parent_pid)


if __name__ == "__main__":
    sys.exit(main())
