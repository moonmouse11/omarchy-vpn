"""Bounded newline-delimited JSON protocol for the per-user status backend.

One request and one response per connection, stdlib only. The client
(`request`) returns None for any transport, protocol or service failure so
the CLI can fall back to the direct implementation; None is its only
failure signal.
"""

import json
import os
import socket
import time
from pathlib import Path

# Requests are tiny ({"op":"status"}); responses carry full status/server
# JSON, so they get a larger but still hard bound.
MAX_REQUEST_BYTES = 4096
MAX_RESPONSE_BYTES = 262144

# Both exceed the measured handler work (~124 ms status) so a healthy
# service never trips them; they only bound a hung one before fallback.
STATUS_TIMEOUT = 2.0
SERVERS_TIMEOUT = 5.0


def socket_path() -> Path | None:
    """Backend socket path, or None when $XDG_RUNTIME_DIR is unset."""
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime_dir:
        return None
    return Path(runtime_dir) / "omarchy-vpn" / "backend.sock"


def _set_remaining_timeout(stream: socket.socket, deadline: float | None) -> None:
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("backend request deadline exceeded")
        stream.settimeout(remaining)


def read_message(stream: socket.socket, *, max_bytes: int, deadline: float | None = None) -> dict:
    """Read one newline-terminated JSON object from `stream`.

    Raises ValueError for malformed JSON, non-object payloads, truncated
    messages, or anything exceeding `max_bytes` — the byte bound is applied
    before parsing.
    """
    buf = bytearray()
    while b"\n" not in buf:
        _set_remaining_timeout(stream, deadline)
        chunk = stream.recv(min(4096, max_bytes + 1 - len(buf)))
        if not chunk:
            raise ValueError("connection closed before end of message")
        buf += chunk
        if len(buf) > max_bytes:
            raise ValueError("message exceeds size limit")
    line = bytes(buf).split(b"\n", 1)[0]
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError("message is not a JSON object")
    return value


def write_message(stream: socket.socket, value: dict, *, deadline: float | None = None) -> None:
    """Write one newline-terminated JSON object within the remaining I/O budget."""
    payload = json.dumps(value, ensure_ascii=False).encode("utf-8") + b"\n"
    _set_remaining_timeout(stream, deadline)
    stream.sendall(payload)


def request(op: str, *, timeout: float) -> dict | None:
    """Ask the backend for `op` and return its result, or None on any failure.

    Accepts only a {"ok": true, "result": <object>} response; anything else
    (connect refused, timeout, malformed or oversized reply, {"ok": false})
    returns None so the caller falls back to the direct path.
    """
    path = socket_path()
    if path is None:
        return None
    payload = json.dumps({"op": op}, ensure_ascii=False).encode("utf-8") + b"\n"
    if len(payload) > MAX_REQUEST_BYTES:
        return None
    deadline = time.monotonic() + timeout
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            _set_remaining_timeout(sock, deadline)
            sock.connect(str(path))
            _set_remaining_timeout(sock, deadline)
            sock.sendall(payload)
            message = read_message(sock, max_bytes=MAX_RESPONSE_BYTES, deadline=deadline)
    except OSError, ValueError:
        return None
    if message.get("ok") is not True:
        return None
    result = message.get("result")
    return result if isinstance(result, dict) else None
