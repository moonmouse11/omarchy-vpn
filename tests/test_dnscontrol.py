"""The root DNS broker accepts slot/type, never caller destinations or payloads."""

import importlib
import importlib.util
import os
import socket
import struct
import threading

import pytest


def control():
    assert importlib.util.find_spec("vpn_dns.control") is not None, (
        "fixed DNS socket broker is missing"
    )
    return importlib.import_module("vpn_dns.control")


def test_dns_socket_fixes_uplink_mark_and_destination_port(monkeypatch):
    mod = control()
    calls = []

    class Socket:
        def setsockopt(self, *args):
            calls.append(("option", *args))

        def settimeout(self, value):
            calls.append(("timeout", value))

        def connect(self, address):
            calls.append(("connect", address))

        def close(self):
            calls.append(("close",))

    fake = Socket()
    monkeypatch.setattr(mod.os, "setgroups", lambda groups: None)
    monkeypatch.setattr(mod.socket, "socket", lambda family, kind: fake)
    assert mod.dns_socket("192.0.2.53", False, "eth0", os.getuid(), os.getgid()) is fake
    assert ("option", socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"eth0\0") in calls
    assert ("option", socket.SOL_SOCKET, socket.SO_MARK, mod.DNS_MARK) in calls
    assert ("connect", ("192.0.2.53", 53)) in calls
    for invalid in ("example.com", "127.0.0.1", "0.0.0.0", "224.0.0.1", "::1"):
        with pytest.raises(ValueError):
            mod.dns_socket(invalid, False, "eth0", os.getuid(), os.getgid())


@pytest.mark.parametrize("fail", [False, True])
def test_dns_socket_belongs_to_caller_not_root(monkeypatch, fail):
    mod = control()
    uid, gid, groups = [0], [0], [0, 17]
    created = []
    monkeypatch.setattr(mod.os, "geteuid", lambda: uid[0])
    monkeypatch.setattr(mod.os, "seteuid", lambda value: uid.__setitem__(0, value))
    monkeypatch.setattr(mod.os, "getegid", lambda: gid[0])
    monkeypatch.setattr(mod.os, "setegid", lambda value: gid.__setitem__(0, value))
    monkeypatch.setattr(mod.os, "getgroups", lambda: list(groups))
    monkeypatch.setattr(mod.os, "setgroups", lambda values: groups.__setitem__(slice(None), values))

    class Socket:
        def setsockopt(self, *args):
            assert uid[0] == 0

        def settimeout(self, value):
            pass

        def connect(self, address):
            assert uid[0] == 0

        def close(self):
            pass

    def create(*args):
        created.append((uid[0], gid[0], list(groups)))
        if fail:
            raise OSError("socket creation failed")
        return Socket()

    monkeypatch.setattr(mod.socket, "socket", create)
    if fail:
        with pytest.raises(OSError, match="socket creation failed"):
            mod.dns_socket("192.0.2.53", False, "eth0", 1000, 1001)
    else:
        mod.dns_socket("192.0.2.53", False, "eth0", 1000, 1001)
    assert created == [(1000, 1001, [])]
    assert (uid[0], gid[0], groups) == (0, 0, [0, 17])


def test_endpoint_is_fixed_and_token_is_not_a_path():
    mod = control()
    assert (
        str(mod.endpoint(1000, "a" * 32)) == "/run/user/1000/omarchy-vpn/dns-" + "a" * 32 + ".sock"
    )
    for value in ("../elsewhere", "a" * 31, "A" * 32):
        with pytest.raises(ValueError):
            mod.endpoint(1000, value)


def test_peer_must_be_sudo_caller():
    mod = control()
    channel, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with channel, peer, pytest.raises(PermissionError):
        mod.run_session(channel, os.getuid() + 1, ["192.0.2.53"], "eth0")


@pytest.mark.parametrize("gid", [os.getgid(), 2**31 + 7])
def test_only_predeclared_slot_and_udp_tcp_modes_are_accepted(monkeypatch, gid):
    mod = control()
    calls = []
    unpack = struct.unpack
    peer = struct.pack("iII", os.getpid(), os.getuid(), gid)
    monkeypatch.setattr(mod.struct, "unpack", lambda fmt, data: unpack(fmt, peer))
    dummy, other = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)

    def create(server, tcp, uplink, uid, gid):
        assert uid == os.getuid()
        assert gid == struct.unpack("iII", peer)[2]
        calls.append((server, tcp, uplink))
        return dummy.dup()

    monkeypatch.setattr(mod, "dns_socket", create)
    client, root = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)

    def serve():
        with root:
            mod.run_session(root, os.getuid(), ["192.0.2.53"], "eth0")

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        assert client.recv(1024) == b'["192.0.2.53"]'
        for mode in (b"U", b"T"):
            client.send(mode + b"\0")
            reply, fds, _, _ = socket.recv_fds(client, 2, 1)
            assert reply == b"S" and len(fds) == 1
            os.close(fds[0])
        assert calls == [("192.0.2.53", False, "eth0"), ("192.0.2.53", True, "eth0")]
    finally:
        client.close()
        thread.join(2)
        dummy.close()
        other.close()
    assert not thread.is_alive()


@pytest.mark.parametrize("frame", [b"U\xff", b"X\0", b"U\0host:5353", b"U", b""])
def test_invalid_frames_never_create_sockets(monkeypatch, frame):
    mod = control()
    monkeypatch.setattr(mod, "dns_socket", lambda *args: pytest.fail("unvalidated socket request"))
    client, root = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)

    def serve():
        with root:
            mod.run_session(root, os.getuid(), ["192.0.2.53"], "eth0")

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        client.recv(1024)
        client.send(frame)
        if not frame:
            client.shutdown(socket.SHUT_WR)
        assert client.recv(2) == b""
    finally:
        client.close()
        thread.join(2)
    assert not thread.is_alive()
