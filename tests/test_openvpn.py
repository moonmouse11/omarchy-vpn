import pytest

from providers import openvpn
from providers.base import VPNConnection
from providers.openvpn import OpenVPNProvider


def _conn():
    return VPNConnection(name="nl", provider="OpenVPN", active=False)


def test_connect_and_disconnect_go_through_the_helper(monkeypatch):
    """Profile names only: the helper finds the config and the PID file and
    runs openvpn with its fixed flags (openvpn-dns-updown, see test_helper)."""
    calls = []
    monkeypatch.setattr(openvpn, "run_helper", lambda *a, **kw: calls.append(a) or (0, ""))
    provider = OpenVPNProvider()
    assert provider.connect(_conn()).success
    assert provider.disconnect(_conn()).success
    assert calls == [("up", "ovpn", "nl"), ("down", "ovpn", "nl")]


def test_connect_failure_surfaces_message(monkeypatch):
    monkeypatch.setattr(openvpn, "run_helper", lambda *a, **kw: (1, "boom"))
    result = OpenVPNProvider().connect(_conn())
    assert not result.success
    assert result.message == "boom"


def test_disconnect_not_running(monkeypatch):
    monkeypatch.setattr(openvpn, "run_helper", lambda *a, **kw: (1, "error: not running: nl"))
    assert OpenVPNProvider().disconnect(_conn()).message == "Not running: nl"


def test_import_pipes_the_config_and_reports_a_refusal(tmp_path, monkeypatch):
    monkeypatch.setattr(openvpn, "OVPN_DIR", tmp_path / "dest")
    src = tmp_path / "us.ovpn"
    src.write_text("client\nremote h 1194\nup /tmp/x\n")
    seen = []

    def helper(*args, stdin=None, **kw):
        seen.append((args, stdin))
        return 1, "error: this OpenVPN config has a directive the helper doesn't allow (up): …"

    monkeypatch.setattr(openvpn, "run_helper", helper)
    result = OpenVPNProvider().import_config(str(src))
    assert seen == [(("import", "ovpn", "us"), src.read_text())]
    assert not result.success
    assert result.message.startswith("this OpenVPN config has a directive")


def test_delete_refuses_active_profile(monkeypatch):
    conn = VPNConnection(name="nl", provider="OpenVPN", active=True)
    monkeypatch.setattr(openvpn, "run_helper", lambda *a, **kw: pytest.fail("must not run helper"))
    result = OpenVPNProvider().delete_config(conn)
    assert not result.success
    assert "Disconnect" in result.message


def test_delete_runs_helper_rm(monkeypatch, tmp_path):
    monkeypatch.setattr(openvpn, "OVPN_DIR", tmp_path)
    (tmp_path / "nl.conf").write_text("client\n")
    calls = []
    monkeypatch.setattr(openvpn, "run_helper", lambda *a, **kw: calls.append(a) or (0, ""))
    monkeypatch.setattr(OpenVPNProvider, "autostart_enabled", lambda self, n: False)
    assert OpenVPNProvider().delete_config(_conn()).success
    assert calls == [("rm", "ovpn", "nl")]


def test_toggle_autostart(monkeypatch):
    calls = []
    monkeypatch.setattr(openvpn, "run_helper", lambda *a, **kw: calls.append(a) or (0, ""))
    monkeypatch.setattr(OpenVPNProvider, "autostart_enabled", lambda self, n: False)
    assert OpenVPNProvider().toggle_autostart(_conn()).success
    assert calls == [("autostart", "ovpn", "nl", "on")]


def test_delete_config_not_found(monkeypatch, tmp_path):
    monkeypatch.setattr(openvpn, "OVPN_DIR", tmp_path)
    assert not OpenVPNProvider().delete_config(_conn()).success


def test_delete_autostart_disable_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(openvpn, "OVPN_DIR", tmp_path)
    (tmp_path / "nl.conf").write_text("client\n")

    def helper(*args):
        if args[0] == "autostart":
            return 1, "disable failed"
        return 0, ""

    monkeypatch.setattr(openvpn, "run_helper", helper)
    monkeypatch.setattr(OpenVPNProvider, "autostart_enabled", lambda self, n: True)
    result = OpenVPNProvider().delete_config(_conn())
    assert not result.success
    assert "Failed to disable autostart" in result.message


def test_delete_rm_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(openvpn, "OVPN_DIR", tmp_path)
    (tmp_path / "nl.conf").write_text("client\n")
    monkeypatch.setattr(openvpn, "run_helper", lambda *a: (1, "rm failed"))
    monkeypatch.setattr(OpenVPNProvider, "autostart_enabled", lambda self, n: False)
    result = OpenVPNProvider().delete_config(_conn())
    assert not result.success
    assert "Failed to delete" in result.message


def test_delete_accepts_ovpn_extension(monkeypatch, tmp_path):
    monkeypatch.setattr(openvpn, "OVPN_DIR", tmp_path)
    (tmp_path / "nl.ovpn").write_text("client\n")
    calls = []
    monkeypatch.setattr(openvpn, "run_helper", lambda *a: calls.append(a) or (0, ""))
    monkeypatch.setattr(OpenVPNProvider, "autostart_enabled", lambda self, n: False)
    assert OpenVPNProvider().delete_config(_conn()).success
    assert calls == [("rm", "ovpn", "nl")]


def test_toggle_autostart_refuses_active_profile(monkeypatch):
    conn = VPNConnection(name="nl", provider="OpenVPN", active=True)
    monkeypatch.setattr(openvpn, "run_helper", lambda *a, **kw: pytest.fail("must not run"))
    result = OpenVPNProvider().toggle_autostart(conn)
    assert not result.success
    assert "Disconnect" in result.message


def test_toggle_autostart_disables_when_enabled(monkeypatch):
    calls = []
    monkeypatch.setattr(openvpn, "run_helper", lambda *a, **kw: calls.append(a) or (0, ""))
    monkeypatch.setattr(OpenVPNProvider, "autostart_enabled", lambda self, n: True)
    result = OpenVPNProvider().toggle_autostart(_conn())
    assert result.success
    assert "disabled" in result.message
    assert calls == [("autostart", "ovpn", "nl", "off")]


def test_autostart_enabled_reads_systemctl(monkeypatch):
    monkeypatch.setattr(openvpn, "_run", lambda cmd: (0, "enabled"))
    assert OpenVPNProvider().autostart_enabled("nl") is True
    monkeypatch.setattr(openvpn, "_run", lambda cmd: (1, "disabled"))
    assert OpenVPNProvider().autostart_enabled("nl") is False


def test_run_times_out(monkeypatch):
    import subprocess

    def expire(*a, **kw):
        raise subprocess.TimeoutExpired(["systemctl"], 6)

    monkeypatch.setattr(openvpn.subprocess, "run", expire)
    code, msg = openvpn._run(["systemctl", "is-enabled", "openvpn-client@nl"])
    assert code == 1
    assert "timeout" in msg


def test_delete_disables_autostart_before_rm(monkeypatch, tmp_path):
    monkeypatch.setattr(openvpn, "OVPN_DIR", tmp_path)
    (tmp_path / "nl.conf").write_text("client\n")
    calls = []
    monkeypatch.setattr(openvpn, "run_helper", lambda *a, **kw: calls.append(a) or (0, ""))
    monkeypatch.setattr(OpenVPNProvider, "autostart_enabled", lambda self, n: True)
    assert OpenVPNProvider().delete_config(_conn()).success
    assert calls == [("autostart", "ovpn", "nl", "off"), ("rm", "ovpn", "nl")]
