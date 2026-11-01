"""Startup is acknowledged by the unprivileged core, never by TUN existence alone."""

import io
import json
import os
import socket
import subprocess
from unittest.mock import Mock

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
