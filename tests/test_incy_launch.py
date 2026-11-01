"""Startup is acknowledged by the unprivileged core, never by TUN existence alone."""

import io
import json
import os
import socket
import struct
import subprocess
from unittest.mock import MagicMock, Mock

import pytest

from incy import keeper, launcher, xray, xray_run


@pytest.fixture
def core_library(monkeypatch, tmp_path):
    library = tmp_path / "libincycore.so"
    library.touch()
    monkeypatch.setattr(xray, "_incy_library", lambda: library)


@pytest.mark.parametrize(
    "payload", [b'{"error":"bad config"}', b"{}", b'{"ready":1}', b"broken", b""]
)
def test_readiness_rejects_error_malformed_or_premature_exit(payload):
    read, write = os.pipe()
    os.write(write, payload)
    os.close(write)
    try:
        with pytest.raises(OSError):
            xray_run.await_ready(read, 0.1)
    finally:
        os.close(read)


def test_readiness_requires_explicit_success():
    read, write = os.pipe()
    os.write(write, b'{"ready":true}')
    os.close(write)
    try:
        xray_run.await_ready(read, 0.1)
    finally:
        os.close(read)


def test_readiness_timeout():
    read, write = os.pipe()
    try:
        with pytest.raises(OSError, match="timed out"):
            xray_run.await_ready(read, 0.01)
    finally:
        os.close(read)
        os.close(write)


@pytest.mark.parametrize(
    "mode,payload,count",
    [
        ("connect", b"N", 0),
        ("probe", b"T", 1),
        ("connect", b"T", 2),
        ("probe", b"broken", 0),
    ],
)
def test_bad_handshake_closes_received_fds(mode, payload, count):
    from pathlib import Path

    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with client, server:
        before = len(list(Path("/proc/self/fd").iterdir()))
        socket.send_fds(server, [payload], [server.fileno()] * count)
        with pytest.raises(OSError):
            launcher.receive_tun(client, mode)
        assert len(list(Path("/proc/self/fd").iterdir())) == before


def test_send_config_is_bounded_and_readiness_has_no_secret(monkeypatch, core_library):
    captured = []

    class Process:
        pid = 123
        stdin = None

        def poll(self):
            return None

        def terminate(self):
            pass

        def wait(self, **kw):
            return 0

    class Input:
        def write(self, raw):
            captured.append(raw)

        def close(self):
            pass

    calls = []

    def spawn(cmd, **kw):
        calls.append(cmd)
        os.write(kw["pass_fds"][0], b'{"ready":true}')
        process = Process()
        process.stdin = Input()
        return process

    monkeypatch.setattr(xray_run.subprocess, "Popen", spawn)
    proc = xray_run.popen_xray({"secret": "not-in-argv"}, xray_run.PROBE_CFG)
    assert proc.pid == 123
    assert json.loads(captured[0]) == {"secret": "not-in-argv"}
    assert "not-in-argv" not in " ".join(calls[0])
    assert "sudo" not in calls[0]
    assert "incy.launcher" in calls[0]


@pytest.mark.parametrize("slot", [xray_run.KEEPER_CFG, xray_run.PROBE_CFG])
def test_invalid_structure_never_starts_launcher(monkeypatch, tmp_path, slot):
    library = tmp_path / "libincycore.so"
    library.touch()
    monkeypatch.setattr(xray, "_incy_library", lambda: library)
    spawn = Mock(side_effect=AssertionError("launched invalid config"))
    monkeypatch.setattr(xray_run.subprocess, "Popen", spawn)
    with pytest.raises(OSError, match="outbounds"):
        xray_run.popen_xray({"outbounds": [None]}, slot)
    spawn.assert_not_called()


def test_cancellation_during_readiness_terminates_and_reaps_launcher(monkeypatch, core_library):
    process = Mock(stdin=io.BytesIO())
    process.wait.side_effect = [subprocess.TimeoutExpired("launcher", 3), 0]
    monkeypatch.setattr(xray_run.subprocess, "Popen", lambda *a, **kw: process)
    monkeypatch.setattr(xray_run, "await_ready", Mock(side_effect=keeper.KeeperCancelled))
    with pytest.raises(keeper.KeeperCancelled):
        xray_run.popen_xray({}, xray_run.KEEPER_CFG)
    process.terminate.assert_called_once_with()
    process.kill.assert_called_once_with()
    assert process.wait.call_count == 2
    assert process.stdin.closed


@pytest.fixture
def session(monkeypatch, tmp_path):
    path = tmp_path / ("incy-" + "a" * 32 + ".sock")
    monkeypatch.setattr(launcher, "endpoint", lambda uid, token: path)
    monkeypatch.setattr(launcher, "watch_parent", lambda pid: None)
    channel = MagicMock()
    channel.__enter__.return_value = channel
    channel.getsockopt.return_value = struct.pack("3i", 123, 0, 0)
    channel.detach.return_value = 123
    listener = MagicMock()
    listener.__enter__.return_value = listener
    listener.accept.return_value = (channel, None)
    monkeypatch.setattr(launcher.socket, "socket", lambda *args: listener)
    process = Mock(stderr=io.BytesIO(b"helper refused session"))
    process.poll.return_value = None
    spawn = Mock(return_value=process)
    monkeypatch.setattr(launcher.subprocess, "Popen", spawn)
    monkeypatch.setattr(launcher, "receive_tun", lambda channel, mode: None)
    monkeypatch.setattr(launcher, "asset_dir", lambda: None)
    monkeypatch.setattr(launcher, "incy_library", lambda: "/unused/libincycore.so")
    core = Mock(return_value=0)
    monkeypatch.setattr(launcher.worker, "main", core)
    replies = []
    monkeypatch.setattr(launcher.worker, "notify_ready", lambda fd, data: replies.append(data))
    return listener, channel, process, spawn, core, replies


@pytest.mark.parametrize("mode", ["", "--help", "connect;id", "CONNECT", "probe\n"])
def test_launcher_rejects_nonliteral_modes_before_sudo(session, mode):
    _, _, _, spawn, core, replies = session
    assert launcher.run(mode, 7, os.getpid()) == 1
    spawn.assert_not_called()
    core.assert_not_called()
    assert "Invalid INCY session mode" in replies[0]["error"]


@pytest.mark.parametrize("mode", ["connect", "probe"])
def test_launcher_passes_only_fixed_helper_mode_and_token(session, mode):
    _, _, process, spawn, core, replies = session
    assert launcher.run(mode, 7, os.getpid()) == 0
    args = spawn.call_args.args[0]
    assert args[:5] == ["sudo", "-n", launcher.HELPER, "incy-network", mode]
    assert len(args[5]) == 32
    assert all(char in "0123456789abcdef" for char in args[5])
    assert core.call_args.args[0][-2:] == ["--broker-fd", "123"]
    assert replies == []
    process.wait.assert_called_once_with(timeout=8)
    assert process.stderr.closed


@pytest.mark.parametrize("failure", ["wrong-peer", "helper-exit", "timeout", "bad-handshake"])
def test_launcher_reports_startup_failures_without_starting_core(monkeypatch, session, failure):
    listener, channel, process, _, core, replies = session
    if failure == "wrong-peer":
        channel.getsockopt.return_value = struct.pack("3i", 123, 1000, 1000)
        expected = "must run as root"
    elif failure == "bad-handshake":
        monkeypatch.setattr(launcher, "receive_tun", Mock(side_effect=OSError("bad handshake")))
        expected = "bad handshake"
    else:
        listener.accept.side_effect = TimeoutError
        if failure == "helper-exit":
            process.poll.return_value = 1
            expected = "helper refused session"
        else:
            monkeypatch.setattr(launcher, "START_TIMEOUT", -1)
            expected = "timed out"
    assert launcher.run("connect", 7, os.getpid()) == 1
    assert expected in replies[0]["error"]
    core.assert_not_called()
    process.wait.assert_called_once_with(timeout=8)
    assert process.stderr.closed
