"""Tests for the persistent serial backend service."""

import json
import runpy
import socket
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

import app.servers
import app.status
import backendipc
import backendservice

_MANAGER = Path(__file__).resolve().parent.parent / "src" / "vpn_manager.py"


def test_dispatch_status_calls_get_status(monkeypatch):
    monkeypatch.setattr(app.status, "get_status", lambda: {"state": "up"})
    assert backendservice.dispatch("status") == {"state": "up"}


def test_dispatch_servers_calls_server_list(monkeypatch):
    monkeypatch.setattr(app.servers, "server_list", lambda: {"servers": []})
    assert backendservice.dispatch("servers") == {"servers": []}


def test_dispatch_invalidate_is_a_noop_success():
    # No daemon-owned memoized values exist yet; invalidate must succeed
    # without touching on-disk caches (which it never references).
    assert backendservice.dispatch("invalidate") == {}


def test_dispatch_unknown_operation_raises():
    with pytest.raises(ValueError):
        backendservice.dispatch("explode")


def _wait_ready(path: Path) -> None:
    deadline = time.monotonic() + 5
    while True:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.connect(str(path))
            return
        except OSError:
            assert time.monotonic() < deadline, "service did not start listening"
            time.sleep(0.01)


def _start_service(path: Path) -> threading.Thread:
    thread = threading.Thread(target=backendservice.serve, kwargs={"path": path}, daemon=True)
    thread.start()
    _wait_ready(path)
    return thread


def _call(path: Path, payload: bytes, timeout: float = 2.0) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(str(path))
        sock.sendall(payload)
        return backendipc.read_message(sock, max_bytes=backendipc.MAX_RESPONSE_BYTES)


def _request(path: Path, op: str, timeout: float = 2.0) -> dict:
    return _call(path, json.dumps({"op": op}).encode() + b"\n", timeout)


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setattr(app.status, "get_status", lambda: {"kind": "status"})
    monkeypatch.setattr(app.servers, "server_list", lambda: {"kind": "servers"})
    path = tmp_path / "omarchy-vpn" / "backend.sock"
    _start_service(path)
    return path


def test_service_serves_status_then_servers(service):
    assert _request(service, "status") == {"ok": True, "result": {"kind": "status"}}
    assert _request(service, "servers") == {"ok": True, "result": {"kind": "servers"}}


def test_service_sequential_clients_get_complete_responses(service):
    first = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    second = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    with first, second:
        first.settimeout(2.0)
        second.settimeout(2.0)
        first.connect(str(service))
        first.sendall(b'{"op": "status"}\n')
        second.connect(str(service))
        second.sendall(b'{"op": "servers"}\n')
        reply_first = backendipc.read_message(first, max_bytes=backendipc.MAX_RESPONSE_BYTES)
        reply_second = backendipc.read_message(second, max_bytes=backendipc.MAX_RESPONSE_BYTES)
    assert reply_first == {"ok": True, "result": {"kind": "status"}}
    assert reply_second == {"ok": True, "result": {"kind": "servers"}}


def test_service_reports_handler_error_and_survives(service, monkeypatch):
    def boom():
        raise RuntimeError("handler exploded")

    monkeypatch.setattr(app.status, "get_status", boom)
    reply = _request(service, "status")
    assert reply["ok"] is False
    assert "handler exploded" in reply["error"]
    # The listener survives: the next request succeeds.
    monkeypatch.setattr(app.status, "get_status", lambda: {"kind": "status"})
    assert _request(service, "status") == {"ok": True, "result": {"kind": "status"}}


def test_service_reports_unknown_operation_and_survives(service):
    reply = _request(service, "explode")
    assert reply["ok"] is False
    assert _request(service, "status")["ok"] is True


def test_service_reports_malformed_json_and_survives(service):
    reply = _call(service, b"not json\n")
    assert reply["ok"] is False
    assert _request(service, "status")["ok"] is True


def test_service_disconnects_stalled_client_and_serves_next(service, monkeypatch):
    monkeypatch.setattr(backendservice, "_CONNECTION_TIMEOUT", 0.2)
    stalled = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    with stalled:
        stalled.connect(str(service))  # sends nothing, just holds the connection
        # Serial service must time the stalled client out and still answer.
        reply = _request(service, "status", timeout=5.0)
    assert reply == {"ok": True, "result": {"kind": "status"}}


def test_service_socket_is_user_only(service):
    mode = stat.S_IMODE(service.stat().st_mode)
    assert mode == 0o600


def test_service_runtime_dir_is_private(tmp_path, monkeypatch):
    monkeypatch.setattr(app.status, "get_status", dict)
    path = tmp_path / "omarchy-vpn" / "backend.sock"
    _start_service(path)
    mode = stat.S_IMODE(path.parent.stat().st_mode)
    assert mode == 0o700


def test_service_removes_stale_socket_file(tmp_path, monkeypatch):
    monkeypatch.setattr(app.status, "get_status", lambda: {"kind": "status"})
    path = tmp_path / "omarchy-vpn" / "backend.sock"
    path.parent.mkdir(parents=True)
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(path))
    stale.close()  # leaves a dead socket file owned by the current user
    _start_service(path)
    assert _request(path, "status") == {"ok": True, "result": {"kind": "status"}}


def test_service_refuses_to_unlink_regular_file(tmp_path):
    path = tmp_path / "omarchy-vpn" / "backend.sock"
    path.parent.mkdir(parents=True)
    path.write_text("precious user data")
    with pytest.raises(OSError):
        backendservice.serve(path=path)
    assert path.read_text() == "precious user data"


def test_serve_without_runtime_dir_exits(monkeypatch):
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    with pytest.raises(SystemExit):
        backendservice.serve()


def test_vpn_manager_backend_service_entry(monkeypatch, tmp_path):
    """Bare --backend-service takes an early branch into backendservice.serve."""
    calls = []
    monkeypatch.setattr(backendservice, "serve", lambda: calls.append("serve"))
    monkeypatch.setattr(sys, "argv", [str(_MANAGER), "--backend-service"])
    with pytest.raises(SystemExit):
        runpy.run_path(str(_MANAGER), run_name="__main__")
    assert calls == ["serve"]
