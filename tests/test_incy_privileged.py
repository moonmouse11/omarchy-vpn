"""Root-side operations are fixed and happen only after caller authentication."""

import contextlib
import json
import os
import signal
import socket
import struct
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest

from incy import privileged


@pytest.mark.parametrize("uid", [None, "", "0", "-1", "../1", "1\n", "abc"])
def test_rejects_missing_or_invalid_sudo_identity(monkeypatch, uid):
    monkeypatch.setattr(privileged.os, "geteuid", lambda: 0)
    if uid is None:
        monkeypatch.delenv("SUDO_UID", raising=False)
    else:
        monkeypatch.setenv("SUDO_UID", uid)
    with pytest.raises(PermissionError):
        privileged.caller_uid()


def test_requires_root_even_with_valid_sudo_uid(monkeypatch):
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setattr(privileged.os, "geteuid", lambda: 1000)
    with pytest.raises(PermissionError):
        privileged.caller_uid()


def test_accepts_numeric_sudo_uid(monkeypatch):
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setattr(privileged.os, "geteuid", lambda: 0)
    assert privileged.caller_uid() == 1000


@pytest.mark.parametrize("token", ["", "a" * 31, "a" * 33, "../" + "a" * 29, "A" * 32])
def test_endpoint_rejects_non_token_paths(token):
    with pytest.raises(ValueError):
        privileged.endpoint(1000, token)


def test_endpoint_is_fixed_under_runtime_directory():
    assert str(privileged.endpoint(1000, "a" * 32)) == (
        "/run/user/1000/omarchy-vpn/incy-" + "a" * 32 + ".sock"
    )


def test_uplink_skips_active_tunnels(monkeypatch):
    def ip(*args):
        if args == ("-json", "-details", "link", "show"):
            return json.dumps(
                [
                    {"ifname": "wg0", "linkinfo": {"info_kind": "wireguard"}},
                    {"ifname": "happ-xray", "linkinfo": {"info_kind": "tun"}},
                    {"ifname": "eth0"},
                ]
            )
        assert args == ("-json", "route", "show", "default")
        return json.dumps(
            [
                {"dev": "wg0", "metric": 0},
                {"dev": "happ-xray", "metric": 1},
                {"dev": "eth0", "metric": 600},
            ]
        )

    monkeypatch.setattr(privileged, "_ip", ip)
    assert privileged.uplink_interface() == "eth0"


def test_no_uplink_fails_closed(monkeypatch):
    monkeypatch.setattr(privileged, "_ip", lambda *args: "[]")
    with pytest.raises(OSError, match="uplink"):
        privileged.uplink_interface()


def test_probe_session_never_creates_tunnel(monkeypatch):
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    create = Mock()
    monkeypatch.setattr(privileged, "tunnel", create)
    monkeypatch.setattr(privileged, "serve", lambda *_: None)
    with client, server:
        privileged.run_session(server, "probe", os.getuid(), "eth0")
        assert client.recv(1) == b"N"
    create.assert_not_called()


def test_peer_mismatch_is_rejected_before_network_changes(monkeypatch):
    channel = Mock(family=socket.AF_UNIX, type=socket.SOCK_SEQPACKET)
    channel.getsockopt.return_value = struct.pack("3i", 123, 2000, 2000)
    create = Mock()
    monkeypatch.setattr(privileged, "tunnel", create)
    with pytest.raises(PermissionError):
        privileged.run_session(channel, "connect", 1000, "eth0")
    create.assert_not_called()
    channel.send.assert_not_called()


def test_main_rejects_wrong_peer_before_uplink_probe(monkeypatch):
    channel = MagicMock()
    channel.__enter__.return_value = channel
    channel.getsockopt.return_value = struct.pack("3i", 123, 2000, 2000)
    monkeypatch.setattr(privileged, "caller_uid", lambda: 1000)
    monkeypatch.setattr(privileged.socket, "socket", lambda *args: channel)
    uplink = Mock()
    monkeypatch.setattr(privileged, "uplink_interface", uplink)
    assert privileged.main(["connect", "a" * 32]) == 1
    uplink.assert_not_called()


def test_kernel_tun_creation_is_exclusive(monkeypatch):
    with Path("/dev/null").open("rb") as resource:
        fd = os.dup(resource.fileno())
        monkeypatch.setattr(privileged.os, "open", lambda *args: fd)
        ioctl = Mock()
        monkeypatch.setattr(privileged.fcntl, "ioctl", ioctl)
        try:
            assert privileged._new_tun() == fd
            ioctl.assert_called_once_with(fd, 0x400454CA, struct.pack("16sH", b"incy-xray", 0x9001))
        finally:
            os.close(fd)


def test_termination_shutdowns_channel_and_restores_handler():
    previous = signal.getsignal(signal.SIGTERM)
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with client, server, privileged.shutdown_on_signal(client):
        callback = signal.getsignal(signal.SIGTERM)
        assert callable(callback)
        callback(signal.SIGTERM, None)
        assert server.recv(1) == b""
    assert signal.getsignal(signal.SIGTERM) == previous


@pytest.fixture
def tun(monkeypatch):
    monkeypatch.setattr(privileged, "_switch_lock", contextlib.nullcontext)
    monkeypatch.setattr(privileged, "_interface_exists", lambda: False)
    monkeypatch.setattr(privileged, "_new_tun", lambda: os.open("/dev/null", os.O_RDONLY))
    calls = []
    monkeypatch.setattr(privileged, "_ip", lambda *args: calls.append(args))
    return calls


def test_tunnel_uses_only_fixed_addresses_and_routes_and_cleans_up(tun):
    with privileged.tunnel() as fd:
        os.fstat(fd)
    with pytest.raises(OSError):
        os.fstat(fd)
    assert tun == [
        ("address", "add", "172.19.0.2/30", "dev", "incy-xray"),
        ("link", "set", "dev", "incy-xray", "mtu", "1500", "up"),
        ("route", "add", "0.0.0.0/1", "dev", "incy-xray"),
        ("route", "add", "128.0.0.0/1", "dev", "incy-xray"),
        ("link", "delete", "dev", "incy-xray"),
    ]


def test_tunnel_rolls_back_partial_setup(tun, monkeypatch):
    def fail_second_route(*args):
        tun.append(args)
        if args[:3] == ("route", "add", "128.0.0.0/1"):
            raise OSError("route conflict")

    monkeypatch.setattr(privileged, "_ip", fail_second_route)
    with pytest.raises(OSError, match="route conflict"), privileged.tunnel():
        pytest.fail("must not hand out a partially configured tunnel")
    assert tun[-1] == ("link", "delete", "dev", "incy-xray")


def test_existing_tunnel_is_not_touched(tun, monkeypatch):
    monkeypatch.setattr(privileged, "_interface_exists", lambda: True)
    with pytest.raises(FileExistsError), privileged.tunnel():
        pytest.fail("must not take over another owner's interface")
    assert tun == []
