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
        return 1, "error: this OpenVPN config runs scripts or writes files as root (up)"

    monkeypatch.setattr(openvpn, "run_helper", helper)
    result = OpenVPNProvider().import_config(str(src))
    assert seen == [(("import", "ovpn", "us"), src.read_text())]
    assert not result.success
    assert result.message.startswith("this OpenVPN config runs scripts")
