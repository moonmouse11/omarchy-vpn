"""Unprivileged endpoint resolver never opens an ordinary DNS socket."""

import contextlib
import importlib
import importlib.util
import os
import socket
import struct
import threading
import time
from types import SimpleNamespace

import pytest


class ReplySocket:
    def __init__(self, data):
        self.data = data
        self.sent = b""
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def settimeout(self, timeout):
        assert timeout > 0

    def sendall(self, data):
        self.sent += data

    def recv(self, size):
        data, self.data = self.data[:size], self.data[size:]
        return data


def bootstrap():
    assert importlib.util.find_spec("vpn_dns.bootstrap") is not None, "scoped DNS client is missing"
    return importlib.import_module("vpn_dns.bootstrap")


def test_explicit_denial_keeps_channel_paired_and_received_socket_is_cloexec():
    mod = bootstrap()
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    outgoing = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    outgoing.connect(("127.0.0.1", 53))

    def serve():
        with right:
            right.settimeout(1)
            right.recv(2)
            right.sendall(b"E")
            if right.recv(2):
                socket.send_fds(right, [b"S"], [outgoing.fileno()])

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        client = mod.Client(left, ["192.0.2.53", "127.0.0.1"], time.monotonic() + 1)
        with pytest.raises(OSError):
            client._socket(0, False)
        assert left.fileno() >= 0, "an explicit refusal must not poison a later request"
        with client._socket(1, False) as received:
            assert not os.get_inheritable(received.fileno())
            assert received.getpeername() == ("127.0.0.1", 53)
    finally:
        left.close()
        thread.join(2)
        outgoing.close()
    assert not thread.is_alive()


def test_literals_do_not_launch_privileged_helper(monkeypatch):
    mod = bootstrap()
    monkeypatch.setattr(mod, "_session", lambda *args: pytest.fail("literal launched helper"))
    assert mod.resolve(["192.0.2.1"]) == {"192.0.2.1": "192.0.2.1"}


def test_ipv4_hosts_overrides_do_not_query_dns(monkeypatch, tmp_path):
    mod = bootstrap()
    hosts = tmp_path / "hosts"
    hosts.write_bytes(
        b"# legacy comment: \xff\n::1 ipv6-only\ninvalid ignored\n"
        b"192.0.2.44 VPN.EXAMPLE alias # comment\n"
        b"192.0.2.45 vpn.example\n0.0.0.0 blocked.example\n"
    )
    monkeypatch.setattr(mod, "HOSTS_FILE", hosts, raising=False)
    monkeypatch.setattr(mod, "_session", lambda *a: pytest.fail("hosts override queried DNS"))
    assert mod.resolve(["vpn.example", "ALIAS.", "blocked.example"]) == {
        "vpn.example": "192.0.2.44",
        "ALIAS.": "192.0.2.44",
        "blocked.example": "0.0.0.0",
    }


@pytest.mark.parametrize("contents", [None, "::1 vpn.example\ninvalid vpn.example\n"])
def test_missing_or_non_ipv4_hosts_uses_configured_dns(monkeypatch, tmp_path, contents):
    mod = bootstrap()
    hosts = tmp_path / "hosts"
    if contents is not None:
        hosts.write_text(contents)
    monkeypatch.setattr(mod, "HOSTS_FILE", hosts)

    @contextlib.contextmanager
    def session(deadline):
        yield SimpleNamespace(query=lambda host: "192.0.2.8")

    monkeypatch.setattr(mod, "_session", session)
    assert mod.resolve(["vpn.example"]) == {"vpn.example": "192.0.2.8"}


def test_truncated_udp_retries_same_question_over_tcp_and_closes_both(monkeypatch):
    mod = bootstrap()
    monkeypatch.setattr(mod.secrets, "randbits", lambda bits: 0x1234)
    question = mod.dnswire.query("vpn.example", 0x1234)
    truncated = question[:2] + struct.pack("!5H", 0x8380, 1, 0, 0, 0) + question[12:]
    full = (
        question[:2]
        + struct.pack("!5H", 0x8180, 1, 1, 0, 0)
        + question[12:]
        + b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 30, 4)
        + b"\xc0\x00\x02\x01"
    )
    udp, tcp = ReplySocket(truncated), ReplySocket(struct.pack("!H", len(full)) + full)
    client = mod.Client(None, ["192.0.2.53"], time.monotonic() + 2)
    calls = []
    monkeypatch.setattr(
        client,
        "_socket",
        lambda slot, is_tcp: calls.append((slot, is_tcp)) or (tcp if is_tcp else udp),
    )
    assert client.query("vpn.example") == "192.0.2.1"
    assert calls == [(0, False), (0, True)]
    assert udp.sent == question
    assert tcp.sent == struct.pack("!H", len(question)) + question
    assert udp.closed and tcp.closed


@pytest.mark.parametrize("rcode", [1, 2, 4, 5])
@pytest.mark.parametrize("tcp", [False, True])
def test_server_error_tries_healthy_configured_secondary(monkeypatch, rcode, tcp):
    mod = bootstrap()
    monkeypatch.setattr(mod.secrets, "randbits", lambda bits: 0x1234)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a: pytest.fail("libc DNS called"))
    question = mod.dnswire.query("vpn.example", 0x1234)
    error = question[:2] + struct.pack("!5H", 0x8180 | rcode, 1, 0, 0, 0) + question[12:]
    truncated = question[:2] + struct.pack("!5H", 0x8380, 1, 0, 0, 0) + question[12:]
    healthy = (
        question[:2]
        + struct.pack("!5H", 0x8180, 1, 1, 0, 0)
        + question[12:]
        + b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 30, 4)
        + b"\xc0\x00\x02\x07"
    )
    client = mod.Client(None, ["192.0.2.53", "192.0.2.54"], time.monotonic() + 1)
    calls = []

    def reply(slot, is_tcp):
        calls.append((slot, is_tcp))
        data = healthy if slot == 1 else (truncated if tcp and not is_tcp else error)
        return ReplySocket(struct.pack("!H", len(data)) + data if is_tcp else data)

    monkeypatch.setattr(client, "_socket", reply)
    assert client.query("vpn.example") == "192.0.2.7"
    assert calls == ([(0, False), (0, True), (1, False)] if tcp else [(0, False), (1, False)])


@pytest.mark.parametrize("rcode", [0, 3])
def test_nodata_and_nxdomain_do_not_query_secondary(monkeypatch, rcode):
    mod = bootstrap()
    monkeypatch.setattr(mod.secrets, "randbits", lambda bits: 0x1234)
    question = mod.dnswire.query("vpn.example", 0x1234)
    negative = question[:2] + struct.pack("!5H", 0x8180 | rcode, 1, 0, 0, 0) + question[12:]
    client = mod.Client(None, ["192.0.2.53", "192.0.2.54"], time.monotonic() + 1)

    def reply(slot, tcp):
        assert slot == 0 and not tcp, "terminal negative must not bypass the configured resolver"
        return ReplySocket(negative)

    monkeypatch.setattr(client, "_socket", reply)
    assert client.query("vpn.example") is None


@pytest.mark.parametrize("expire", [False, True])
def test_all_server_errors_remain_bounded_by_original_deadline(monkeypatch, expire):
    mod = bootstrap()
    monkeypatch.setattr(mod.secrets, "randbits", lambda bits: 0x1234)
    question = mod.dnswire.query("vpn.example", 0x1234)
    error = question[:2] + struct.pack("!5H", 0x8182, 1, 0, 0, 0) + question[12:]
    client = mod.Client(None, ["192.0.2.53", "192.0.2.54"], time.monotonic() + 1)
    calls = []

    def reply(slot, tcp):
        calls.append(slot)
        if expire:
            assert slot == 0, "deadline was reset during failover"
        stream = ReplySocket(error)
        if expire:

            def expired_reply(size):
                client.deadline = time.monotonic() - 1
                return error

            monkeypatch.setattr(stream, "recv", expired_reply)
        return stream

    monkeypatch.setattr(client, "_socket", reply)
    assert client.query("vpn.example") is None
    assert calls == ([0] if expire else [0, 1])


def test_missing_answer_and_exhausted_deadline_do_not_fall_back_to_libc(monkeypatch):
    mod = bootstrap()
    monkeypatch.setattr(mod.secrets, "randbits", lambda bits: 0x1234)
    question = mod.dnswire.query("vpn.example", 0x1234)
    nx = question[:2] + struct.pack("!5H", 0x8183, 1, 0, 0, 0) + question[12:]
    client = mod.Client(None, ["192.0.2.53"], time.monotonic() + 1)
    monkeypatch.setattr(client, "_socket", lambda *args: ReplySocket(nx))
    assert client.query("vpn.example") is None
    client.deadline = time.monotonic() - 1
    monkeypatch.setattr(client, "_socket", lambda *args: pytest.fail("query beyond deadline"))
    assert client.query("vpn.example") is None
