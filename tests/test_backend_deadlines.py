"""Whole-message deadlines cannot be extended by a trickling socket peer."""

import contextlib
import socket
import threading
import time

import pytest

import backendipc
import backendservice


def test_client_deadline_bounds_a_trickling_response(tmp_path, monkeypatch):
    path = tmp_path / "s"
    monkeypatch.setattr(backendipc, "socket_path", lambda: path)
    finished = threading.Event()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        listener.listen()

        def respond():
            with listener.accept()[0] as conn:
                conn.recv(4096)
                try:
                    for byte in b'{"ok":true,"result":{}}\n':
                        conn.sendall(bytes([byte]))
                        time.sleep(0.025)
                except OSError:
                    pass
                finally:
                    finished.set()

        thread = threading.Thread(target=respond, daemon=True)
        thread.start()
        start = time.monotonic()
        assert backendipc.request("status", timeout=0.1) is None
        assert time.monotonic() - start < 0.4
        assert finished.wait(2)
        thread.join(2)


def test_accepted_connection_deadline_stops_a_trickling_client(monkeypatch):
    monkeypatch.setattr(backendservice, "_CONNECTION_TIMEOUT", 0.1)
    calls = []
    monkeypatch.setattr(backendservice, "dispatch", lambda op: calls.append(op) or {})
    client, server = socket.socketpair()
    with client, server:
        thread = threading.Thread(target=backendservice._handle, args=(server,), daemon=True)
        thread.start()
        start = time.monotonic()
        # Every byte arrives sooner than the old per-read timeout. The whole
        # request takes too long; it must not dispatch after the deadline.
        for byte in b'{"op":"status"}\n':
            with contextlib.suppress(OSError):
                client.sendall(bytes([byte]))
            time.sleep(0.02)
        thread.join(0.2)
        assert not thread.is_alive()
        assert calls == []
        assert time.monotonic() - start < 0.6
    # Per-client timeout must not poison subsequent handler requests.
    client, server = socket.socketpair()
    with client, server:
        client.sendall(b'{"op":"status"}\n')
        backendservice._handle(server)
        assert backendipc.read_message(client, max_bytes=1024)["ok"] is True
    assert calls == ["status"]


def test_expired_deadline_is_checked_before_a_read():
    client, server = socket.socketpair()
    with client, server:
        client.sendall(b"{}\n")
        deadline = time.monotonic() - 1
        with pytest.raises(TimeoutError):
            backendipc.read_message(server, max_bytes=1024, deadline=deadline)


def test_handler_finishing_after_deadline_does_not_send_a_late_success(monkeypatch):
    monkeypatch.setattr(backendservice, "_CONNECTION_TIMEOUT", 0.02)

    def slow_handler(op):
        time.sleep(0.04)
        return {}

    monkeypatch.setattr(backendservice, "dispatch", slow_handler)
    client, server = socket.socketpair()
    with client, server:
        client.settimeout(0.1)
        client.sendall(b'{"op":"status"}\n')
        backendservice._handle(server)
        with pytest.raises(TimeoutError):
            client.recv(1)
