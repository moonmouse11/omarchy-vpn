"""Protocol and direct-client tests for the long-lived status backend."""

import json
import socket
import threading
import time
from pathlib import Path

import pytest

import backendipc


def test_socket_path_uses_runtime_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    assert backendipc.socket_path() == tmp_path / "omarchy-vpn" / "backend.sock"


def test_socket_path_missing_runtime_dir_returns_none(monkeypatch):
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    assert backendipc.socket_path() is None


def test_message_round_trip():
    left, right = socket.socketpair()
    with left, right:
        backendipc.write_message(left, {"op": "status"})
        assert backendipc.read_message(right, max_bytes=1024) == {"op": "status"}


def test_write_message_is_newline_terminated_json():
    left, right = socket.socketpair()
    with left, right:
        backendipc.write_message(left, {"ok": True, "result": {"a": "é"}})
        raw = right.recv(4096)
    assert raw.endswith(b"\n")
    assert json.loads(raw.decode("utf-8")) == {"ok": True, "result": {"a": "é"}}


def test_read_message_rejects_malformed_json():
    left, right = socket.socketpair()
    with left, right:
        left.sendall(b"not json\n")
        with pytest.raises(ValueError):
            backendipc.read_message(right, max_bytes=1024)


def test_read_message_rejects_oversized_message():
    left, right = socket.socketpair()
    with left, right:
        left.sendall(b"x" * 2048)
        left.shutdown(socket.SHUT_WR)
        with pytest.raises(ValueError):
            backendipc.read_message(right, max_bytes=1024)


def test_read_message_rejects_non_object_json():
    left, right = socket.socketpair()
    with left, right:
        left.sendall(b"[1, 2, 3]\n")
        with pytest.raises(ValueError):
            backendipc.read_message(right, max_bytes=1024)


def test_read_message_rejects_truncated_message():
    left, right = socket.socketpair()
    with left, right:
        left.sendall(b'{"ok": true')  # EOF before the newline terminator
        left.shutdown(socket.SHUT_WR)
        with pytest.raises(ValueError):
            backendipc.read_message(right, max_bytes=1024)


def _run_server(path: Path, handler) -> threading.Thread:
    """Listen on `path` and run handler(conn) for each accepted connection."""
    path.parent.mkdir(parents=True, exist_ok=True)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen()

    def serve():
        with listener:
            while True:
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                with conn:
                    handler(conn)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


def _use_tmp_socket(monkeypatch, tmp_path) -> Path:
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    return tmp_path / "omarchy-vpn" / "backend.sock"


def test_request_returns_none_without_runtime_dir(monkeypatch):
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    assert backendipc.request("status", timeout=0.2) is None


def test_request_returns_none_when_socket_unavailable(monkeypatch, tmp_path):
    _use_tmp_socket(monkeypatch, tmp_path)  # nothing is listening
    assert backendipc.request("status", timeout=0.2) is None


def test_request_returns_result(monkeypatch, tmp_path):
    path = _use_tmp_socket(monkeypatch, tmp_path)

    def handler(conn):
        assert backendipc.read_message(conn, max_bytes=backendipc.MAX_REQUEST_BYTES) == {
            "op": "status"
        }
        backendipc.write_message(conn, {"ok": True, "result": {"state": "up"}})

    _run_server(path, handler)
    assert backendipc.request("status", timeout=1.0) == {"state": "up"}


def test_request_returns_none_on_error_response(monkeypatch, tmp_path):
    path = _use_tmp_socket(monkeypatch, tmp_path)

    def handler(conn):
        backendipc.read_message(conn, max_bytes=backendipc.MAX_REQUEST_BYTES)
        backendipc.write_message(conn, {"ok": False, "error": "boom"})

    _run_server(path, handler)
    assert backendipc.request("status", timeout=1.0) is None


def test_request_returns_none_on_malformed_response(monkeypatch, tmp_path):
    path = _use_tmp_socket(monkeypatch, tmp_path)

    def handler(conn):
        backendipc.read_message(conn, max_bytes=backendipc.MAX_REQUEST_BYTES)
        conn.sendall(b"garbage\n")

    _run_server(path, handler)
    assert backendipc.request("status", timeout=1.0) is None


def test_request_returns_none_on_oversized_response(monkeypatch, tmp_path):
    path = _use_tmp_socket(monkeypatch, tmp_path)

    def handler(conn):
        backendipc.read_message(conn, max_bytes=backendipc.MAX_REQUEST_BYTES)
        conn.sendall(b"x" * (backendipc.MAX_RESPONSE_BYTES + 1))

    _run_server(path, handler)
    assert backendipc.request("status", timeout=1.0) is None


def test_request_returns_none_when_server_never_responds(monkeypatch, tmp_path):
    path = _use_tmp_socket(monkeypatch, tmp_path)

    def handler(conn):
        backendipc.read_message(conn, max_bytes=backendipc.MAX_REQUEST_BYTES)
        time.sleep(2)  # accepts but never responds within the client timeout

    _run_server(path, handler)
    start = time.monotonic()
    assert backendipc.request("status", timeout=0.2) is None
    assert time.monotonic() - start < 1.0


def test_constants_are_bounded_and_ordered():
    assert backendipc.MAX_REQUEST_BYTES > 0
    assert backendipc.MAX_RESPONSE_BYTES >= backendipc.MAX_REQUEST_BYTES
    assert backendipc.STATUS_TIMEOUT > 0
    assert backendipc.SERVERS_TIMEOUT > 0
