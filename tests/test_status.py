import pytest

import config
import vpn_manager
from happ.constants import MANAGER
from providers.base import ActionResult, VPNConnection


class FakeProvider:
    def __init__(self, name, conns):
        self.name = name
        self._conns = conns

    def connections(self):
        return self._conns


def patch_env(
    monkeypatch, providers, cfg=None, traffic="↓ 1 MiB  ↑ 2 MiB", rate="↓ 3 KiB/s ↑ 4 KiB/s"
):
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", providers)
    monkeypatch.setattr(vpn_manager.config, "load_config", lambda: cfg or config.Config())
    monkeypatch.setattr(vpn_manager, "iface_traffic", lambda iface: traffic)
    monkeypatch.setattr(vpn_manager, "iface_rate", lambda iface: rate)
    monkeypatch.setattr(vpn_manager, "sample_iface_traffic", lambda iface: None)
    monkeypatch.setattr(vpn_manager, "request_ip_update", lambda name: None)
    monkeypatch.setattr(vpn_manager.ipinfo, "status_line", lambda conn, age: "Exit: 9.9.9.9")


def test_request_ip_update_spawns_vpn_manager(monkeypatch):
    argv = []

    def popen(cmd, **kw):
        argv.append(cmd)

    monkeypatch.setattr(vpn_manager.subprocess, "Popen", popen)
    vpn_manager.request_ip_update("nl")
    assert argv == [[vpn_manager.sys.executable, str(MANAGER), "--update-ip", "nl"]]


def test_request_dns_autotest_spawns_vpn_manager(monkeypatch):
    argv = []

    def popen(cmd, **kw):
        argv.append(cmd)

    monkeypatch.setattr(vpn_manager.subprocess, "Popen", popen)
    vpn_manager.request_dns_autotest()
    assert argv == [[vpn_manager.sys.executable, str(MANAGER), "--dns-autotest"]]


def test_disconnected(monkeypatch):
    patch_env(monkeypatch, [])
    status = vpn_manager.get_status()
    assert status["class"] == "vpn-disconnected"
    assert status["text"] == " VPN"


def test_single_active(monkeypatch):
    conn = VPNConnection(name="nl", provider="WireGuard", active=True, interface="wg0")
    patch_env(monkeypatch, [FakeProvider("WireGuard", [conn])])
    status = vpn_manager.get_status()
    assert status["text"] == " WireGuard: nl"
    assert status["class"] == ["vpn-connected", "vpn-wireguard"]
    assert "↓ 3 KiB/s ↑ 4 KiB/s" in status["tooltip"]  # rate, units per second
    assert "↓ 1 MiB  ↑ 2 MiB total" in status["tooltip"]  # totals, marked
    assert "Exit: 9.9.9.9" in status["tooltip"]


def test_multiple_active(monkeypatch):
    wg = VPNConnection(name="nl", provider="WireGuard", active=True, interface="wg0")
    happ = VPNConnection(name="de", provider="Happ", active=True)
    patch_env(monkeypatch, [FakeProvider("WireGuard", [wg]), FakeProvider("Happ", [happ])])
    status = vpn_manager.get_status()
    assert status["text"] == " WireGuard: nl (+1)"
    assert status["class"] == ["vpn-connected", "vpn-wireguard", "vpn-happ"]
    assert "Happ: de" in status["tooltip"]


def test_a_hidden_providers_tunnel_still_counts(monkeypatch):
    """⚙ Settings hides a protocol from the server list — a tunnel it has up
    (WireGuard autostart, NM) is still traffic in a tunnel, not "off"."""
    conn = VPNConnection(name="x", provider="Outline", active=True)
    cfg = config.Config(providers={"outline": False})
    patch_env(monkeypatch, [FakeProvider("Outline", [conn])], cfg=cfg)
    status = vpn_manager.get_status()
    assert "vpn-connected" in status["class"]


@pytest.mark.parametrize(
    ("up", "ipv6_off", "guard", "disabled"),
    [
        (True, False, True, True),
        (True, True, True, False),
        (False, False, True, False),
        (True, False, False, False),  # ⚙ IPv6 guard off: the user's call
    ],
)
def test_status_turns_ipv6_off_under_a_tunnel_the_plugin_didnt_start(
    monkeypatch, up, ipv6_off, guard, disabled
):
    """WireGuard autostart at boot: no guarded_connect ran, so --status is
    where IPv6 goes off — only when a tunnel is up, IPv6 is still on and the
    guard is on."""
    conn = VPNConnection(name="nl", provider="WireGuard", active=up)
    patch_env(monkeypatch, [FakeProvider("WireGuard", [conn])], cfg=config.Config(ipv6_guard=guard))
    calls = []
    monkeypatch.setattr(vpn_manager.ipv6guard, "is_disabled", lambda: ipv6_off)
    monkeypatch.setattr(
        vpn_manager.ipv6guard, "disable", lambda: calls.append("disable") or ActionResult(True, "")
    )
    monkeypatch.setattr(
        vpn_manager.ipv6guard, "enable", lambda: pytest.fail("status never enables")
    )
    vpn_manager.get_status()
    assert (calls == ["disable"]) is disabled


def test_no_traffic_when_no_interface(monkeypatch):
    conn = VPNConnection(name="de", provider="Happ", active=True, interface=None)
    patch_env(monkeypatch, [FakeProvider("Happ", [conn])], traffic=None)
    status = vpn_manager.get_status()
    assert "↓" not in status["tooltip"]


def test_connection_label_with_and_without_subscription():
    plain = VPNConnection(name="nl", provider="WireGuard", active=True)
    happ = VPNConnection(
        name="🇩🇪 Germany", provider="Happ", active=True, subscription_name="Provider C"
    )
    assert plain.label == "WireGuard: nl"
    assert happ.label == "Happ · Provider C: 🇩🇪 Germany"


def test_happ_status_shows_subscription_provider(monkeypatch):
    conn = VPNConnection(
        name="🇩🇪 Germany",
        provider="Happ",
        active=True,
        interface="happ-xray",
        subscription_id="1",
        subscription_name="Provider C",
    )
    patch_env(monkeypatch, [FakeProvider("Happ", [conn])])
    status = vpn_manager.get_status()
    assert status["text"] == " Happ · Provider C: 🇩🇪 Germany"
    assert "Happ · Provider C: 🇩🇪 Germany" in status["tooltip"]
