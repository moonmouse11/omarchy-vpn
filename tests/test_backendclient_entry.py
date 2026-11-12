"""Early bare --status/--servers IPC client paths in vpn_manager.__main__."""

import json
import runpy
import sys
from pathlib import Path

import pytest
from test_status import _hermetic_status_env, patch_env

import app.cli
import app.status
import backendipc

SRC = Path(__file__).resolve().parent.parent / "src"
_MANAGER = SRC / "vpn_manager.py"

_HEAVY = ("app.status", "app.servers", "app.cli")


def _run_manager(monkeypatch, capsys, flag: str) -> str:
    monkeypatch.setattr(sys, "argv", [str(_MANAGER), flag])
    with pytest.raises(SystemExit):
        runpy.run_path(str(_MANAGER), run_name="__main__")
    return capsys.readouterr().out


def _drop_heavy_modules(monkeypatch) -> None:
    for name in _HEAVY:
        monkeypatch.delitem(sys.modules, name, raising=False)


def test_status_served_over_ipc(monkeypatch, capsys):
    result = {"text": " VéP", "class": "vpn-disconnected", "tooltip": "t", "panel": {}}
    calls = []

    def fake_request(op, *, timeout):
        calls.append((op, timeout))
        return result

    monkeypatch.setattr(backendipc, "request", fake_request)
    _drop_heavy_modules(monkeypatch)
    out = _run_manager(monkeypatch, capsys, "--status")
    assert calls == [("status", backendipc.STATUS_TIMEOUT)]
    # --status keeps json.dumps' default ASCII escaping, one document + newline
    assert out == json.dumps(result) + "\n"
    assert "\\u00e9" in out
    for name in _HEAVY:
        assert name not in sys.modules


def test_servers_served_over_ipc(monkeypatch, capsys):
    result = {"groups": [], "providers": [{"name": "Vé"}]}
    calls = []

    def fake_request(op, *, timeout):
        calls.append((op, timeout))
        return result

    monkeypatch.setattr(backendipc, "request", fake_request)
    _drop_heavy_modules(monkeypatch)
    out = _run_manager(monkeypatch, capsys, "--servers")
    assert calls == [("servers", backendipc.SERVERS_TIMEOUT)]
    # --servers keeps ensure_ascii=False, one document + newline
    assert out == json.dumps(result, ensure_ascii=False) + "\n"
    assert "Vé" in out
    for name in _HEAVY:
        assert name not in sys.modules


def test_status_falls_back_to_direct_once(monkeypatch, tmp_path, capsys):
    _hermetic_status_env(tmp_path)
    patch_env(monkeypatch, [])
    requests = []
    monkeypatch.setattr(backendipc, "request", lambda op, *, timeout: requests.append(op) or None)
    real_get_status = app.status.get_status
    direct_calls = []
    monkeypatch.setattr(
        app.status, "get_status", lambda: direct_calls.append(1) or real_get_status()
    )
    out = _run_manager(monkeypatch, capsys, "--status")
    assert requests == ["status"]
    assert direct_calls == [1]  # direct implementation ran exactly once
    assert out.endswith("\n")
    assert out.count("\n") == 1
    data = json.loads(out)
    assert data["class"] == "vpn-disconnected"


def test_servers_falls_back_to_direct_once(monkeypatch, capsys):
    canned = {"groups": [{"title": "Vé"}], "providers": []}
    monkeypatch.setattr(backendipc, "request", lambda op, *, timeout: None)
    direct_calls = []
    monkeypatch.setattr(app.cli, "server_list", lambda: direct_calls.append(1) or canned)
    out = _run_manager(monkeypatch, capsys, "--servers")
    assert direct_calls == [1]
    assert out == json.dumps(canned, ensure_ascii=False) + "\n"


@pytest.mark.parametrize("flag", ["--bogus-flag", "--status", "--servers"])
def test_only_bare_status_and_servers_use_ipc(monkeypatch, capsys, flag):
    called = []
    monkeypatch.setattr(
        backendipc,
        "request",
        lambda op, *, timeout: called.append(op) or {"ok": True},
    )
    monkeypatch.setattr(app.cli, "main", lambda: None)
    argv = [str(_MANAGER), flag] if flag == "--bogus-flag" else [str(_MANAGER), flag, "extra"]
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit):
        runpy.run_path(str(_MANAGER), run_name="__main__")
    assert called == []  # non-bare argv never touches IPC
