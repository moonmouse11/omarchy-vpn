"""Persistent serial backend service for --status/--servers.

One foreground process, one accepted connection at a time: serial handling
avoids races in the existing provider/cache code. systemd owns restart; this
module never daemonizes, forks, or writes PID files. Every per-connection
error is converted to {"ok": false, ...} so the listener survives.
"""

import contextlib
import os
import socket
import stat
import time
from pathlib import Path

import backendipc

# Stall guard on accepted connections: the service is serial, so a client
# that connects but never finishes its request must not block every later
# client forever. Exceeds backendipc.SERVERS_TIMEOUT so healthy clients
# always time out on their own side first.
_CONNECTION_TIMEOUT = 10.0


def dispatch(op: str) -> object:
    """Run one backend operation and return its JSON-serializable result."""
    if op == "status":
        from app.status import get_status  # noqa: PLC0415 — lazy: keep the app graph out of client/import paths

        return get_status()
    if op == "servers":
        from app.servers import server_list  # noqa: PLC0415 — lazy, same reason

        return server_list()
    if op == "invalidate":
        # No daemon-owned memoized values exist yet; on-disk caches stay
        # the source of truth and are deliberately not touched here.
        return {}
    raise ValueError(f"unknown operation: {op}")


def _remove_stale_socket(path: Path) -> None:
    """Unlink a stale socket path, but never an arbitrary user file."""
    try:
        st = path.lstat()
    except FileNotFoundError:
        return
    if not (stat.S_ISSOCK(st.st_mode) and st.st_uid == os.getuid()):
        raise OSError(f"refusing to replace non-socket path: {path}")
    path.unlink()


def _handle(conn: socket.socket) -> None:
    deadline = time.monotonic() + _CONNECTION_TIMEOUT
    conn.settimeout(_CONNECTION_TIMEOUT)
    try:
        message = backendipc.read_message(
            conn, max_bytes=backendipc.MAX_REQUEST_BYTES, deadline=deadline
        )
        response: dict = {"ok": True, "result": dispatch(str(message.get("op")))}
    except Exception as exc:  # noqa: BLE001 — the listener must survive any per-connection failure
        response = {"ok": False, "error": str(exc) or type(exc).__name__}
    # client vanished or result not serializable; keep listening
    with contextlib.suppress(OSError, TypeError, ValueError):
        backendipc.write_message(conn, response, deadline=deadline)


def serve(path: Path | None = None) -> None:
    """Listen on the backend socket and serve requests serially, forever."""
    if path is None:
        path = backendipc.socket_path()
    if path is None:
        raise SystemExit("backendservice: XDG_RUNTIME_DIR is not set")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)  # mkdir mode is a no-op when the dir exists
    _remove_stale_socket(path)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        # Bind under a umask that yields 0600 — never wider, even briefly.
        old_umask = os.umask(0o177)
        try:
            listener.bind(str(path))
        finally:
            os.umask(old_umask)
        listener.listen()
        while True:
            conn, _ = listener.accept()
            with conn:
                _handle(conn)
    finally:
        listener.close()
        path.unlink(missing_ok=True)
