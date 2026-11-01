"""Real SCM_RIGHTS transport; privileged socket operations are injected at the boundary."""

import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path

import pytest

from incy import broker


@pytest.mark.parametrize(
    "payload,count", [(b"X", 1), (b"PPPPP", 1), (b"P", 0), (b"P", 2), (b"P", 12)]
)
def test_rejects_malformed_requests_without_fd_leaks(payload, count):
    client, server = pair()
    applied = []
    with client, server, socket.socket() as outgoing:
        client.settimeout(2)
        thread = threading.Thread(target=broker.serve, args=(server, applied.append))
        thread.start()
        try:
            before = len(list(Path("/proc/self/fd").iterdir()))
            socket.send_fds(client, [payload], [outgoing.fileno()] * count)
            assert client.recv(2) == b"0"
            assert not applied
            assert len(list(Path("/proc/self/fd").iterdir())) == before
        finally:
            client.shutdown(socket.SHUT_RDWR)
            thread.join(2)
        assert not thread.is_alive()


def test_concurrent_requests_keep_replies_paired():
    client, server = pair()

    def apply(sock):
        if not sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE):
            raise OSError("denied")

    with client, server, ExitStack() as resources:
        sockets = [resources.enter_context(socket.socket()) for _ in range(12)]
        for index, outgoing in enumerate(sockets):
            outgoing.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, index % 2)
        thread = threading.Thread(target=broker.serve, args=(server, apply))
        thread.start()
        try:
            channel = broker.Client(client)
            with ThreadPoolExecutor(max_workers=6) as pool:
                results = list(pool.map(lambda sock: channel.protect(sock.fileno()), sockets))
            assert results == [False, True] * 6
        finally:
            client.shutdown(socket.SHUT_RDWR)
            thread.join(2)
        assert not thread.is_alive()


def test_timeout_permanently_disables_channel(monkeypatch):
    monkeypatch.setattr(broker, "TIMEOUT", 0.02)
    client, server = pair()
    with client, server, socket.socket() as outgoing:
        channel = broker.Client(client)
        assert channel.protect(outgoing.fileno()) is False
        assert client.fileno() == -1
        assert channel.protect(outgoing.fileno()) is False


def pair():
    return socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)


def test_protect_transfers_socket_and_waits_for_success():
    seen = []
    with socket.socket() as outgoing:
        client, server = pair()
        with client, server:

            def apply(sock):
                assert not os.get_inheritable(sock.fileno())
                seen.append((sock.family, sock.type))
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

            thread = threading.Thread(target=broker.serve, args=(server, apply))
            thread.start()
            try:
                assert broker.Client(client).protect(outgoing.fileno()) is True
                assert outgoing.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 1
                assert seen == [(socket.AF_INET, socket.SOCK_STREAM)]
            finally:
                client.shutdown(socket.SHUT_RDWR)
                thread.join(2)
            assert not thread.is_alive()


@pytest.mark.parametrize("kind", ["file", "unix", "listener", "connected"])
def test_rejects_non_outbound_descriptors(kind, tmp_path):
    client, server = pair()
    applied = []
    with client, server:
        if kind == "file":
            resource = (tmp_path / "file").open("w+b")
        elif kind == "unix":
            resource = socket.socket(socket.AF_UNIX)
        else:
            resource = socket.socket()
            resource.bind(("127.0.0.1", 0))
            resource.listen()
        peer = None
        if kind == "connected":
            peer = socket.create_connection(resource.getsockname())
            accepted, _ = resource.accept()
            resource.close()
            resource = accepted
        try:
            thread = threading.Thread(target=broker.serve, args=(server, applied.append))
            thread.start()
            assert broker.Client(client).protect(resource.fileno()) is False
            assert not applied
        finally:
            client.shutdown(socket.SHUT_RDWR)
            thread.join(2)
            resource.close()
            if peer:
                peer.close()
        assert not thread.is_alive()


def test_broker_failure_denies_and_can_process_next_socket():
    client, server = pair()
    with client, server, socket.socket() as outgoing:

        def fail(_sock):
            raise OSError("cannot bind uplink")

        thread = threading.Thread(target=broker.serve, args=(server, fail))
        thread.start()
        try:
            channel = broker.Client(client)
            assert channel.protect(outgoing.fileno()) is False
            assert channel.protect(outgoing.fileno()) is False
        finally:
            client.shutdown(socket.SHUT_RDWR)
            thread.join(2)
        assert not thread.is_alive()


def test_dead_broker_fails_closed():
    client, server = pair()
    server.close()
    with client, socket.socket() as outgoing:
        channel = broker.Client(client)
        assert channel.protect(outgoing.fileno()) is False
        assert channel.protect(outgoing.fileno()) is False


def test_received_fd_is_closed_after_request():
    received = []
    client, server = pair()
    with client, server, socket.socket() as outgoing:
        thread = threading.Thread(target=broker.serve, args=(server, received.append))
        thread.start()
        try:
            assert broker.Client(client).protect(outgoing.fileno())
            assert received[0].fileno() == -1
            os.fstat(outgoing.fileno())
        finally:
            client.shutdown(socket.SHUT_RDWR)
            thread.join(2)
        assert not thread.is_alive()
