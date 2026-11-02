"""Bootstrap startup and cancellation cannot leave listeners or received FDs open."""

import io
import os
import socket
import time
from types import SimpleNamespace

import pytest

from vpn_dns import bootstrap


def test_helper_start_failure_unlinks_listener(monkeypatch, tmp_path):
    path = tmp_path / "bootstrap.sock"
    monkeypatch.setattr(bootstrap, "endpoint", lambda uid, token: path)

    def fail(*args, **kwargs):
        raise OSError("helper unavailable")

    monkeypatch.setattr(bootstrap.subprocess, "Popen", fail)
    with (
        pytest.raises(OSError, match="helper unavailable"),
        bootstrap._session(time.monotonic() + 1),
    ):
        pytest.fail("session must not start")
    assert not path.exists()


def test_cancelled_start_closes_listener_and_reaps_helper(monkeypatch, tmp_path):
    class Cancelled(BaseException):
        pass

    path = tmp_path / "bootstrap.sock"
    waits = []
    listeners = []
    stderr = io.BytesIO()
    proc = SimpleNamespace(stderr=stderr, wait=lambda **kwargs: waits.append(kwargs))
    monkeypatch.setattr(bootstrap, "endpoint", lambda uid, token: path)
    monkeypatch.setattr(bootstrap.subprocess, "Popen", lambda *args, **kwargs: proc)

    def cancel(listener, process, deadline):
        listeners.append(listener)
        raise Cancelled

    monkeypatch.setattr(bootstrap, "_accept", cancel)
    with pytest.raises(Cancelled), bootstrap._session(time.monotonic() + 1):
        pytest.fail("session must not start")
    assert not path.exists()
    assert listeners[0].fileno() == -1
    assert waits == [{"timeout": 2}]
    assert stderr.closed


def test_non_socket_descriptor_is_closed_and_channel_poisoned(monkeypatch):
    received = []
    receive = bootstrap._receive

    def capture(*args):
        data, fd = receive(*args)
        received.append(fd)
        return data, fd

    monkeypatch.setattr(bootstrap, "_receive", capture)
    read_fd, write_fd = os.pipe()
    try:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with left, right:
            socket.send_fds(right, [b"S"], [read_fd])
            client = bootstrap.Client(left, ["192.0.2.53"], time.monotonic() + 1)
            with pytest.raises(OSError):
                client._socket(0, False)
            assert left.fileno() == -1
            assert client._lock.acquire(blocking=False)
            client._lock.release()
            assert len(received) == 1
            with pytest.raises(OSError):
                os.fstat(received[0])
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_authenticated_helper_policy_error_is_preserved(monkeypatch):
    monkeypatch.setattr(bootstrap, "require_peer_uid", lambda channel, uid: None)
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with left, right:
        right.sendall(b'{"error":"required TLS; refusing plaintext bootstrap"}')
        with pytest.raises(OSError, match="required TLS"):
            bootstrap._upstreams(left, time.monotonic() + 1)
