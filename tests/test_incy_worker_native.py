"""Opt-in real INCY ABI checks; run only in a disposable no-network container.

Set INCY_TEST_LIBRARY to the read-only mounted libincycore.so. No host TUN is needed.
"""

import os
import socket
from contextlib import suppress
from pathlib import Path

import pytest

from incy.worker import Core

LIBRARY = os.environ.get("INCY_TEST_LIBRARY", "")
pytestmark = pytest.mark.skipif(not LIBRARY, reason="INCY bundled library not mounted")


def test_native_core_starts_and_stops_without_tun():
    core = Core(LIBRARY)
    try:
        core.start({"inbounds": [], "outbounds": [{"protocol": "blackhole"}]})
        assert core.running()
    finally:
        core.stop()
    assert not core.running()


@pytest.mark.parametrize("raises", [False, True])
def test_native_socket_protector_failure_blocks_connection(raises):
    calls = []

    def reject(fd):
        with socket.socket(fileno=os.dup(fd)) as sock:
            calls.append(sock.family)
        if raises:
            raise OSError("broker unavailable")
        return False

    core = Core(LIBRARY)
    with socket.socket() as origin, socket.socket() as reservation:
        origin.bind(("127.0.0.1", 0))
        origin.listen()
        origin.settimeout(0.2)
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        reservation.close()
        target = origin.getsockname()[1]
        core.set_socket_protector(reject)
        try:
            core.start(
                {
                    "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "http"}],
                    "outbounds": [{"protocol": "freedom"}],
                }
            )
            with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                client.sendall(
                    f"GET http://127.0.0.1:{target}/ HTTP/1.1\r\nHost: localhost\r\n\r\n".encode()
                )
                with suppress(ConnectionResetError):
                    client.recv(4096)
            assert calls
            assert set(calls) == {socket.AF_INET}
            with pytest.raises(TimeoutError):
                origin.accept()
        finally:
            core.stop()


def test_native_socket_protector_allows_connection():
    core = Core(LIBRARY)
    with socket.socket() as origin, socket.socket() as reservation:
        origin.bind(("127.0.0.1", 0))
        origin.listen()
        origin.settimeout(2)
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        reservation.close()
        target = origin.getsockname()[1]
        core.set_socket_protector(lambda _fd: True)
        try:
            core.start(
                {
                    "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "http"}],
                    "outbounds": [{"protocol": "freedom"}],
                }
            )
            with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                client.sendall(
                    f"GET http://127.0.0.1:{target}/ HTTP/1.1\r\nHost: localhost\r\n\r\n".encode()
                )
                conn, _ = origin.accept()
                with conn:
                    conn.settimeout(2)
                    assert b"GET / HTTP/1.1" in conn.recv(4096)
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                assert b"200 OK" in client.recv(4096)
        finally:
            core.stop()


def test_native_core_uses_supplied_fd():
    core = Core(LIBRARY)
    with (
        Path("/dev/null").open("rb") as device,
        pytest.raises(OSError, match="Inappropriate ioctl"),
    ):
        core.start(
            {
                "inbounds": [{"protocol": "tun", "settings": {"name": "incy-test"}}],
                "outbounds": [{"protocol": "blackhole"}],
            },
            tun_fd=device.fileno(),
        )
    assert not core.running()
