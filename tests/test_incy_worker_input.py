"""Bounded stdin transport and worker lifecycle, without loading native code."""

import io
import os
import signal
import socket
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from incy import worker


@pytest.mark.parametrize("raw", [b"[]", b"null", b"{} trailing", b"{", b'"x"'])
def test_config_must_be_one_json_object(raw):
    with pytest.raises(ValueError):
        worker.read_config(io.BytesIO(raw))


def test_config_is_bounded(monkeypatch):
    monkeypatch.setattr(worker, "CONFIG_MAX", 8)
    with pytest.raises(ValueError, match="too large"):
        worker.read_config(io.BytesIO(b'{"123":45}'))


def test_reads_config_without_changing_unicode():
    assert worker.read_config(io.BytesIO('{"remarks":"Польша"}'.encode())) == {"remarks": "Польша"}


def test_closes_core_after_wait_failure():
    core = Mock()
    with pytest.raises(RuntimeError, match="wait failed"):
        worker.serve(core, {}, None, lambda: (_ for _ in ()).throw(RuntimeError("wait failed")))
    core.stop.assert_called_once_with()


def test_waits_until_terminated_or_core_exits():
    core = Mock()
    core.running.side_effect = [True, False]
    wait = Mock(return_value=False)
    worker.serve(core, {}, 7, wait)
    core.start.assert_called_once_with({}, tun_fd=7)
    core.stop.assert_called_once_with()
    wait.assert_called_once_with()


def test_stops_on_termination():
    core = Mock()
    worker.serve(core, {}, None, lambda: True)
    core.stop.assert_called_once_with()


def test_cli_restores_signal_handlers_and_stops_core(monkeypatch):
    core = Mock()
    core.running.return_value = False
    monkeypatch.setattr(worker, "Core", lambda library: core)
    monkeypatch.setattr(worker.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"{}")))
    before = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    assert worker.main(["--library", "/unused/libincycore.so", "--tun-fd", "7"]) == 0
    core.start.assert_called_once_with({}, tun_fd=7)
    core.stop.assert_called_once_with()
    assert {sig: signal.getsignal(sig) for sig in before} == before


def test_cli_reports_native_start_failure(monkeypatch, capsys):
    core = Mock()
    core.start.side_effect = OSError("native startup failed")
    monkeypatch.setattr(worker, "Core", lambda library: core)
    monkeypatch.setattr(worker.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"{}")))
    assert worker.main(["--library", "/unused/libincycore.so"]) == 1
    assert "native startup failed" in capsys.readouterr().err
    core.stop.assert_called_once_with()


def test_broker_loss_detects_remote_and_local_close():
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with client, server:
        assert worker.broker_lost(client) is False
        server.send(b"1")
        assert worker.broker_lost(client) is False
        server.close()
        assert worker.broker_lost(client) is True
        client.close()
        assert worker.broker_lost(client) is True


def test_cli_refuses_non_root_broker_before_loading_library(monkeypatch):
    load = Mock()
    monkeypatch.setattr(worker, "Core", load)
    monkeypatch.setattr(worker.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"{}")))
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with client, server:
        assert (
            worker.main(
                [
                    "--library",
                    "/unused/libincycore.so",
                    "--broker-fd",
                    str(os.dup(client.fileno())),
                ]
            )
            == 1
        )
    load.assert_not_called()


def test_missing_capability_fields_fail_closed(monkeypatch):
    monkeypatch.setattr(worker.os, "getuid", lambda: 1000)
    monkeypatch.setattr(worker.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(worker, "STATUS", Mock(read_text=lambda: "Name:\tpython\n"))
    with pytest.raises(PermissionError):
        worker.require_unprivileged()
