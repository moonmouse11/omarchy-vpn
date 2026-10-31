"""Fast active_connections() paths (--status hot path)."""

import providers.classic.openvpn as openvpn_impl
import providers.openvpn as openvpn
import providers.wireguard as wireguard
from app.registry import active_connections
from providers import networkmanager as nm
from providers.base import VPNConnection
from providers.openvpn import OpenVPNProvider
from providers.wireguard import WireGuardProvider


class _FakeProvider:
    def __init__(self, conns):
        self.name = "Fake"
        self._conns = conns

    def connections(self):
        return self._conns


def test_registry_falls_back_when_provider_has_no_active_method():
    up = VPNConnection("wg0", "Fake", True, interface="wg0")
    assert active_connections(providers=[_FakeProvider([up])]) == [up]


def test_networkmanager_active_connections_only_active_vpns(monkeypatch):
    active_out = "HomeWG:u1:vpn:wg0\nWiFi:u2:802-11-wireless:wlp0\n"

    def fake_run(cmd):
        if cmd == ["nmcli", "-t", "-f", "NAME,UUID,TYPE,DEVICE", "connection", "show", "--active"]:
            return 0, active_out
        return 1, ""

    monkeypatch.setattr(nm.shutil, "which", lambda _: "/usr/bin/nmcli")
    monkeypatch.setattr(nm, "_run", fake_run)
    conns = nm.NetworkManagerProvider().active_connections()
    assert len(conns) == 1
    assert conns[0].name == "HomeWG" and conns[0].interface == "wg0"


def test_openvpn_active_connections_only_running(tmp_path, monkeypatch):
    d = tmp_path / "client"
    d.mkdir()
    (d / "a.conf").write_text("client\n")
    (d / "b.conf").write_text("client\n")
    pid_dir = tmp_path / "run" / "openvpn"
    pid_dir.mkdir(parents=True)
    (pid_dir / "client-a.pid").write_text("1\n")
    monkeypatch.setattr(openvpn, "OVPN_DIR", d)
    monkeypatch.setattr(openvpn, "PID_DIR", pid_dir)
    monkeypatch.setattr(openvpn_impl, "_is_running", lambda profile: profile == "a")
    active = OpenVPNProvider().active_connections()
    assert len(active) == 1
    assert active[0].name == "a" and active[0].active


def test_wireguard_active_connections_skips_glob_when_nothing_up(tmp_path, monkeypatch):
    monkeypatch.setattr(wireguard, "_active_interfaces", lambda *_: [])
    provider = WireGuardProvider()
    provider.config_dir = tmp_path / "wg"
    provider.config_dir.mkdir()
    (provider.config_dir / "home.conf").write_text("[Interface]\n")
    assert provider.active_connections() == []


def test_wireguard_active_connections_lists_up_profiles(tmp_path, monkeypatch):
    monkeypatch.setattr(wireguard, "_active_interfaces", lambda *_: ["home"])
    provider = WireGuardProvider()
    provider.config_dir = tmp_path / "wg"
    provider.config_dir.mkdir()
    (provider.config_dir / "home.conf").write_text("[Interface]\n")
    active = provider.active_connections()
    assert len(active) == 1
    assert active[0].name == "home" and active[0].interface == "home"
