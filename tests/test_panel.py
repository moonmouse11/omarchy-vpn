"""The bar panel's hero + protection badges (vpn_manager.panel_state)."""

import time

import pytest

import config
import killswitch
import vpn_manager
from providers.base import ActionResult, VPNConnection

DE_SERVER = VPNConnection(
    name="🇩🇪 Germany 1",
    provider="Happ",
    active=True,
    interface="happ-xray",
    subscription_id="1",
    subscription_name="ARTEMIDA",
)


@pytest.fixture
def env(monkeypatch):
    """Everything panel_state() reads, as plain knobs."""
    state = {
        "ks_on": False,
        "ipv6_off": True,
        "exit": {"ip": "2.27.59.210", "country_code": "DE", "connection": DE_SERVER.name},
        "fresh": True,
    }
    monkeypatch.setattr(vpn_manager.killswitch, "cached_is_enabled", lambda: state["ks_on"])
    monkeypatch.setattr(vpn_manager.ipv6guard, "is_disabled", lambda: state["ipv6_off"])
    monkeypatch.setattr(vpn_manager.ipinfo, "read_cache", lambda: state["exit"])
    monkeypatch.setattr(vpn_manager.ipinfo, "is_fresh", lambda cache, conn, age: state["fresh"])
    monkeypatch.setattr(vpn_manager.reputation, "country_of", lambda name: None)
    monkeypatch.setattr(vpn_manager, "iface_rate", lambda iface: "↓ 3 KiB/s ↑ 4 KiB/s")
    monkeypatch.setattr(vpn_manager, "iface_traffic", lambda iface: "↓ 1 MiB  ↑ 2 MiB")
    return state


def _panel(active):
    return vpn_manager.panel_state(active, config.Config())


def _badges(panel):
    return {b["id"]: (b["label"], b["state"]) for b in panel["badges"]}


def test_untested_dns_is_unverified_not_protected(env):
    panel = _panel([DE_SERVER])
    assert panel["connected"] is True
    assert (panel["state"], panel["title"]) == ("unverified", "Unverified")
    assert panel["meta"] == "ARTEMIDA: 🇩🇪 Germany 1"  # the pill names the provider
    assert panel["detail"] == "Happ"
    assert panel["exit_ip"] == "2.27.59.210 🇩🇪"
    assert panel["rate"] == "↓ 3 KiB/s ↑ 4 KiB/s"
    assert panel["total"] == "↓ 1 MiB  ↑ 2 MiB"
    assert _badges(panel) == {
        "exit": ("Exit 🇩🇪", "ok"),
        "dns": ("DNS: untested", "unknown"),
        "ipv6": ("IPv6 blocked", "ok"),
        "killswitch": ("Kill switch off", "unknown"),
    }


def test_ipv6_on_under_a_tunnel_is_at_risk(env):
    env["ipv6_off"] = False
    panel = _panel([DE_SERVER])
    assert panel["title"] == "At risk"
    assert _badges(panel)["ipv6"] == ("IPv6 leaks", "bad")


def test_exit_in_another_country_is_at_risk(env):
    env["exit"] = {"ip": "5.6.7.8", "country_code": "NL"}
    panel = _panel([DE_SERVER])
    assert panel["title"] == "At risk"
    assert _badges(panel)["exit"] == ("Exit 🇳🇱 ≠ 🇩🇪", "bad")


def test_exit_unknown_until_looked_up_and_without_a_flag(env):
    env["fresh"] = False
    assert _badges(_panel([DE_SERVER]))["exit"] == ("Exit: checking", "unknown")
    env["fresh"] = True
    plain = VPNConnection(name="office", provider="WireGuard", active=True, interface="wg0")
    panel = _panel([plain])
    assert _badges(panel)["exit"] == ("Exit 🇩🇪", "unknown")  # nothing to compare with
    assert panel["meta"] == "office"
    assert panel["state"] == "unverified"  # an exit with nothing to compare isn't proof


def test_eu_flag_accepts_any_member_state(env):
    eu = VPNConnection(name="🇪🇺 Europe", provider="Happ", active=True)
    env["exit"] = {"ip": "1.1.1.1", "country_code": "PL"}
    assert _badges(_panel([eu]))["exit"][1] == "ok"


def test_disconnected_states(env):
    panel = _panel([])
    assert (panel["connected"], panel["title"]) == (False, "Not protected")
    assert _badges(panel) == {"killswitch": ("Kill switch off", "unknown")}
    env["ks_on"] = True
    panel = _panel([])
    assert panel["title"] == "Traffic blocked"
    assert _badges(panel) == {"killswitch": ("Kill switch on", "ok")}


def test_more_than_one_tunnel_counts_in_the_pill(env):
    other = VPNConnection(name="nl", provider="WireGuard", active=True, interface="wg0")
    assert _panel([DE_SERVER, other])["detail"] == "Happ +1"


@pytest.mark.parametrize(
    ("verdict", "badge"),
    [
        ("DNS via VPN or public resolvers", ("DNS private", "ok")),
        ("Leaked: 2/5 DNS outside VPN/public resolvers", ("DNS leaks", "bad")),
        (None, ("DNS: untested", "unknown")),  # the test had nothing to judge by
    ],
)
def test_dns_badge_follows_the_last_test_for_this_server(env, verdict, badge):
    vpn_manager._save_dns_verdict([DE_SERVER], verdict)
    assert _badges(_panel([DE_SERVER]))["dns"] == badge


def test_dns_verdict_is_per_server_and_expires(env, monkeypatch):
    vpn_manager._save_dns_verdict([DE_SERVER], "DNS via VPN or public resolvers")
    other = VPNConnection(name="🇩🇪 Germany 2", provider="Happ", active=True)
    assert _badges(_panel([other]))["dns"][1] == "unknown"
    later = time.time() + vpn_manager.DNS_VERDICT_MAX_AGE + 1
    monkeypatch.setattr(vpn_manager.time, "time", lambda: later)
    assert _badges(_panel([DE_SERVER]))["dns"][1] == "unknown"


def test_status_carries_the_panel(env, monkeypatch):
    monkeypatch.setattr(vpn_manager, "active_connections", list)
    monkeypatch.setattr(vpn_manager.config, "load_config", config.Config)
    assert vpn_manager.get_status()["panel"]["title"] == "Not protected"


def test_killswitch_state_is_cached_and_dropped_on_change(monkeypatch):
    probes = []
    monkeypatch.setattr(killswitch, "is_enabled", lambda: probes.append(1) or True)
    assert killswitch.cached_is_enabled() is True
    assert killswitch.cached_is_enabled() is True
    assert len(probes) == 1  # the 3 s tick doesn't run sudo every time

    monkeypatch.setattr(
        killswitch.subprocess,
        "run",
        lambda *a, **kw: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})(),
    )
    killswitch.disable()  # any change goes through _sudo()
    assert not killswitch.STATE_CACHE.exists()
    killswitch.cached_is_enabled()
    assert len(probes) == 2


@pytest.mark.parametrize(
    ("flag", "called"),
    [("--disconnect-all", "disconnect_all"), ("--dns-leak-test", "dns_leak_test_menu")],
)
def test_panel_cli_actions(monkeypatch, flag, called):
    calls = []
    monkeypatch.setattr(vpn_manager.sys, "argv", ["vpn_manager.py", flag])
    monkeypatch.setattr(
        vpn_manager,
        "disconnect_all",
        lambda: calls.append("disconnect_all") or ActionResult(True, "ok"),
    )
    monkeypatch.setattr(
        vpn_manager, "dns_leak_test_menu", lambda: calls.append("dns_leak_test_menu")
    )
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **kw: None)
    monkeypatch.setattr(vpn_manager, "refresh_bar", lambda: calls.append("refresh"))
    vpn_manager.main()
    assert calls == [called, "refresh"]


def test_protected_only_after_every_check_passed(env):
    """The lock is earned: exit, DNS and IPv6 all green. The kill switch is
    a preference, not a check — off doesn't withhold it."""
    vpn_manager._save_dns_verdict([DE_SERVER], "DNS via VPN or public resolvers")
    panel = _panel([DE_SERVER])
    assert (panel["state"], panel["title"]) == ("protected", "Protected")
    env["fresh"] = False  # exit not looked up yet
    assert _panel([DE_SERVER])["state"] == "unverified"


def test_disconnected_state_field(env):
    assert _panel([])["state"] == "off"
    env["ks_on"] = True
    assert _panel([])["state"] == "blocked"


class _Provider:
    name = "WireGuard"

    def connections(self):
        return []

    def connect(self, conn):
        return ActionResult(True, "up")


@pytest.mark.parametrize("enabled", [True, False])
def test_dns_autotest_runs_after_a_connect_only_when_enabled(monkeypatch, enabled):
    spawned = []
    monkeypatch.setattr(
        vpn_manager.config, "load_config", lambda: config.Config(dns_autotest=enabled)
    )
    monkeypatch.setattr(vpn_manager.killswitch, "mode", lambda: "off")
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: False)
    monkeypatch.setattr(vpn_manager, "active_connections", lambda providers=None: [])
    monkeypatch.setattr(vpn_manager.ipv6guard, "disable", lambda: ActionResult(True, ""))
    monkeypatch.setattr(vpn_manager, "request_dns_autotest", lambda: spawned.append(1))
    conn = VPNConnection(name="nl", provider="WireGuard", active=False)
    assert vpn_manager.guarded_connect(_Provider(), conn).success
    assert bool(spawned) is enabled


def _autotest_env(monkeypatch, active, result=None, error=None):
    monkeypatch.setattr(vpn_manager, "active_connections", lambda: active)
    monkeypatch.setattr(vpn_manager.time, "sleep", lambda s: None)
    monkeypatch.setattr(vpn_manager, "DNS_AUTOTEST_WAIT", 0)
    monkeypatch.setattr(vpn_manager.logutil, "log", lambda msg: None)

    def run():
        if error:
            raise error
        return result

    monkeypatch.setattr(vpn_manager.dnsleak, "run", run)
    sent, refreshed = [], []
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **kw: sent.append(a))
    monkeypatch.setattr(vpn_manager, "refresh_bar", lambda: refreshed.append(1))
    return sent, refreshed


_CLEAN = {
    "dns_servers": [{"ip": "1.1.1.1", "asn": "AS13335", "country": "DE"}],
    "ip_country": "DE",
    "ip_asn": 64500,
}


def test_dns_autotest_stores_the_verdict_quietly(env, monkeypatch):
    sent, refreshed = _autotest_env(monkeypatch, [DE_SERVER], _CLEAN)
    monkeypatch.setattr(vpn_manager.dnsleak, "server_tags", lambda s, c, a: [])
    vpn_manager.run_dns_autotest()
    assert sent == []  # a pass is silent
    assert refreshed == [1]
    assert _badges(_panel([DE_SERVER]))["dns"] == ("DNS private", "ok")


def test_dns_autotest_announces_a_leak(env, monkeypatch):
    sent, _ = _autotest_env(monkeypatch, [DE_SERVER], _CLEAN)
    monkeypatch.setattr(vpn_manager.dnsleak, "server_tags", lambda s, c, a: ["GEO"])
    vpn_manager.run_dns_autotest()
    assert sent and sent[0][0] == "DNS leak detected"
    assert _badges(_panel([DE_SERVER]))["dns"] == ("DNS leaks", "bad")


def test_dns_autotest_without_a_tunnel_or_on_failure_leaves_it_untested(env, monkeypatch):
    _autotest_env(monkeypatch, [])
    vpn_manager.run_dns_autotest()
    sent, _ = _autotest_env(
        monkeypatch, [DE_SERVER], error=vpn_manager.dnsleak.LeakTestError(2, "timed out")
    )
    vpn_manager.run_dns_autotest()
    assert sent == []
    assert _badges(_panel([DE_SERVER]))["dns"][1] == "unknown"


def test_status_rate_is_read_before_the_tick_saves_a_sample(env, monkeypatch):
    """get_status() samples the traffic counters for the next tick; a rate
    read after that compares against itself — the panel's speed was empty."""
    sampled = []
    monkeypatch.setattr(vpn_manager, "active_connections", lambda: [DE_SERVER])
    monkeypatch.setattr(vpn_manager.config, "load_config", config.Config)
    monkeypatch.setattr(vpn_manager, "sample_iface_traffic", sampled.append)
    monkeypatch.setattr(vpn_manager, "request_ip_update", lambda name: None)
    monkeypatch.setattr(vpn_manager.ipinfo, "status_line", lambda conn, age: None)
    monkeypatch.setattr(
        vpn_manager, "iface_rate", lambda iface: "" if sampled else "↓ 3 KiB/s ↑ 4 KiB/s"
    )
    assert vpn_manager.get_status()["panel"]["rate"] == "↓ 3 KiB/s ↑ 4 KiB/s"
