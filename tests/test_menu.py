import pytest

import config
import vpn_manager
from ipsources.base import IPFinding
from providers.base import ActionResult, VPNConnection


class FakeProvider:
    def __init__(self, name, conns):
        self.name = name
        self._conns = conns
        self.connected = []
        self.disconnected = []

    def connections(self):
        return self._conns

    def connect(self, conn):
        self.connected.append(conn.name)
        return ActionResult(True, f"connected {conn.name}")

    def disconnect(self, conn):
        self.disconnected.append(conn.name)
        return ActionResult(True, f"disconnected {conn.name}")


def patch_menu_env(monkeypatch, providers, picks):
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", providers)
    monkeypatch.setattr(vpn_manager.config, "load_config", config.Config)
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: False)
    monkeypatch.setattr(vpn_manager.killswitch, "mode", lambda: "off")
    # deterministic default: the real ~/.cache/vpn-manager/reputation.json
    # could carry real entries from this machine's own use of the feature
    monkeypatch.setattr(vpn_manager.reputation, "request_update", lambda: None)
    monkeypatch.setattr(vpn_manager, "refresh_bar", lambda: None)
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager, "request_ip_update", lambda name: None)
    # real values only where a test overrides these after calling us (e.g. the
    # metrics-row test below) — real `ip` may be absent (containerized CI)
    monkeypatch.setattr(vpn_manager, "iface_rate", lambda iface: None)
    monkeypatch.setattr(vpn_manager, "iface_traffic", lambda iface: None)
    monkeypatch.setattr(vpn_manager, "sample_iface_traffic", lambda iface: None)


class HappLikeProvider:
    """One disconnect stops everything (like Happ stopping all happd
    processes); later disconnect calls then report 'not connected'."""

    name = "Happ"

    def __init__(self):
        self.calls = 0

    def connections(self):
        active = self.calls == 0
        return [
            VPNConnection(name="Germany", provider="Happ", active=active),
            VPNConnection(name="Germany 4", provider="Happ", active=active),
        ]

    def connect(self, conn):
        return ActionResult(True, "connected")

    def disconnect(self, conn):
        self.calls += 1
        if self.calls == 1:
            return ActionResult(True, "Disconnected: xray-core")
        return ActionResult(False, "Happ is not connected")


def test_disconnect_all_treats_not_connected_as_stopped(monkeypatch):
    happ = HappLikeProvider()
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [happ])
    result = vpn_manager.disconnect_all()
    assert result.success, result.message
    assert "Failed" not in result.message


def test_killswitch_all_mode_arms_wg(monkeypatch, tmp_path):
    """'all' mode: a WireGuard connect rebuilds the whitelist (endpoints +
    tunnel ifaces) instead of suspending the killswitch."""
    monkeypatch.setattr(vpn_manager.killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    cfg = vpn_manager.killswitch.config.load_config()
    cfg.killswitch_mode = "all"
    vpn_manager.killswitch.config.save_config(cfg)
    monkeypatch.setattr(
        vpn_manager, "_killswitch_all_targets", lambda **kw: (["1.2.3.4"], ["nl", "tun*"])
    )
    calls = []
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "enable",
        lambda **kw: calls.append(kw) or ActionResult(True, "on"),
    )
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg])
    result = vpn_manager.guarded_connect(wg, wg.connections()[0])
    assert result.success
    assert wg.connected == ["nl"]
    assert calls == [{"extra_ips": ["1.2.3.4"], "ifaces": ["nl", "tun*"], "dns": []}]


def test_killswitch_connect_opens_dns_only_for_the_connect(monkeypatch, tmp_path):
    """Under the kill switch DNS leaves only through the tunnel — except while
    a connect resolves its endpoints: first pass with port 53 to the system
    resolvers, second pass (after the connect) without."""
    monkeypatch.setattr(vpn_manager.killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    cfg = vpn_manager.killswitch.config.load_config()
    cfg.killswitch_mode = "all"
    vpn_manager.killswitch.config.save_config(cfg)
    monkeypatch.setattr(vpn_manager.killswitch, "system_resolvers", lambda: ["192.168.1.1"])
    monkeypatch.setattr(vpn_manager, "_killswitch_all_targets", lambda **kw: (["1.2.3.4"], ["nl"]))
    order = []
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "enable",
        lambda **kw: order.append(("rules", kw["dns"])) or ActionResult(True, "on"),
    )

    class Wg(FakeProvider):
        def connect(self, conn):
            order.append(("connect", conn.name))
            return super().connect(conn)

    wg = Wg("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg])
    assert vpn_manager.guarded_connect(wg, wg.connections()[0]).success
    assert order == [("rules", ["192.168.1.1"]), ("connect", "nl"), ("rules", [])]


@pytest.mark.parametrize(("lockdown", "expected"), [(True, ["rules"]), (False, ["off"])])
def test_failed_connect_leaves_strict_rules_or_none(monkeypatch, tmp_path, lockdown, expected):
    """A failed connect never keeps the DNS hole: Lockdown keeps the strict
    rules, Lockdown off drops them (nothing is up to protect)."""
    monkeypatch.setattr(vpn_manager.killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    cfg = vpn_manager.killswitch.config.load_config()
    cfg.killswitch_mode = "all"
    cfg.killswitch_lockdown = lockdown
    vpn_manager.killswitch.config.save_config(cfg)
    monkeypatch.setattr(vpn_manager.killswitch, "system_resolvers", lambda: ["192.168.1.1"])
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: True)
    monkeypatch.setattr(vpn_manager, "_killswitch_all_targets", lambda **kw: (["1.2.3.4"], ["nl"]))
    after = []
    connected = []
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "enable",
        lambda **kw: (after.append("rules") if connected else None) or ActionResult(True, "on"),
    )
    monkeypatch.setattr(
        vpn_manager.killswitch, "disable", lambda: after.append("off") or ActionResult(True, "")
    )

    class Broken(FakeProvider):
        def connect(self, conn):
            connected.append(conn.name)
            return ActionResult(False, "handshake timed out")

    wg = Broken("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg])
    assert not vpn_manager.guarded_connect(wg, wg.connections()[0]).success
    assert after == expected


@pytest.mark.parametrize(("lockdown", "released"), [(True, False), (False, True)])
def test_disconnect_drops_the_rules_only_without_lockdown(
    monkeypatch, tmp_path, lockdown, released
):
    monkeypatch.setattr(vpn_manager.config, "CONFIG_PATH", tmp_path / "config.json")
    cfg = vpn_manager.config.load_config()
    cfg.killswitch_lockdown = lockdown
    vpn_manager.config.save_config(cfg)
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: True)
    dropped = []
    monkeypatch.setattr(
        vpn_manager.killswitch, "disable", lambda: dropped.append(1) or ActionResult(True, "")
    )
    conn = VPNConnection(name="nl", provider="WireGuard", active=True)
    wg = FakeProvider("WireGuard", [conn])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg])
    monkeypatch.setattr(vpn_manager, "_sync_ipv6_guard", lambda: None)
    monkeypatch.setattr(vpn_manager, "active_connections", lambda providers=None: [])
    vpn_manager.guarded_disconnect(wg, conn)
    assert bool(dropped) is released


def test_killswitch_is_not_offered_for_networkmanager():
    nm = VPNConnection(name="office", provider="NetworkManager", active=True)
    wg = VPNConnection(name="nl", provider="WireGuard", active=True)
    assert vpn_manager._killswitch_unsupported([nm])
    assert not vpn_manager._killswitch_unsupported([wg])
    assert not vpn_manager._killswitch_unsupported([])


def test_guarded_connect_all_mode_suspends_for_nm(monkeypatch, tmp_path):
    """NetworkManager has no endpoint parser (v1): the killswitch is
    suspended for it even in 'all' mode."""
    monkeypatch.setattr(vpn_manager.killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    cfg = vpn_manager.killswitch.config.load_config()
    cfg.killswitch_mode = "all"
    vpn_manager.killswitch.config.save_config(cfg)
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: True)
    suspended = []
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "suspend_for",
        lambda name: suspended.append(name) or ActionResult(True, "suspended"),
    )
    nm = FakeProvider(
        "NetworkManager", [VPNConnection(name="office", provider="NetworkManager", active=False)]
    )
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [nm])
    result = vpn_manager.guarded_connect(nm, nm.connections()[0])
    assert result.success
    assert suspended == ["NetworkManager"]


def test_guarded_connect_off_mode_suspends_when_enabled(monkeypatch, tmp_path):
    """mode 'off' + killswitch on manually: other providers still suspend it."""
    monkeypatch.setattr(vpn_manager.killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: True)
    suspended = []
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "suspend_for",
        lambda name: suspended.append(name) or ActionResult(True, "suspended"),
    )
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg])
    result = vpn_manager.guarded_connect(wg, wg.connections()[0])
    assert result.success
    assert suspended == ["WireGuard"]


def test_killswitch_all_targets_gathers_wg_and_ovpn_only(monkeypatch):
    """Only WireGuard/OpenVPN endpoints feed the 'all' whitelist; wg profile
    names become allowed interfaces, OpenVPN gets the tun* glob."""

    class PtProvider(FakeProvider):
        def __init__(self, name, targets):
            super().__init__(name, [])
            self._targets = targets

        def ping_targets(self):
            return self._targets

    wg = PtProvider("WireGuard", [("nl", "93.184.216.34", 51820)])
    # >15 chars: never a valid wg interface name (kernel IFNAMSIZ) — the
    # iface is filtered out, but its endpoint IP still joins the whitelist
    # (the config may be driven by NetworkManager, which has no such cap).
    wg_long = PtProvider("WireGuard", [("ThinkPadNetherland", "93.184.216.37", 51820)])
    ovpn = PtProvider("OpenVPN", [("de", "93.184.216.35", 1194)])
    nm = PtProvider("NetworkManager", [("office", "93.184.216.36", 443)])
    broken = PtProvider("WireGuard", [])
    broken.ping_targets = lambda: (_ for _ in ()).throw(OSError("boom"))
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg, wg_long, ovpn, nm, broken])
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "resolve_endpoint_ips",
        lambda targets, **kw: sorted(host for _, host, _ in targets),
    )
    monkeypatch.setattr(
        vpn_manager.happmeta, "subscription_targets", lambda: [("P", "93.184.216.40", 443)]
    )
    ips, ifaces = vpn_manager._killswitch_all_targets()
    # NM endpoint excluded; the Happ subscription host joins so refreshes still work
    assert ips == ["93.184.216.34", "93.184.216.35", "93.184.216.37", "93.184.216.40"]
    assert ifaces == ["nl", "tun*"]  # wg profile name + OpenVPN glob; long name filtered


def test_happ_connect_passes_resolved_server_ip(monkeypatch, tmp_path):
    """guarded_connect(Happ) resolves the target server and hands its IP to
    resume_for_happ — otherwise the killswitch blocks xray from the server."""
    happ = FakeProvider("Happ", [VPNConnection(name="de", provider="Happ", active=False)])
    patch_menu_env(monkeypatch, [happ], picks=[])
    monkeypatch.setattr(
        vpn_manager.happmeta,
        "server_endpoints",
        lambda name, **kw: [("de.example.com", 443), ("de2.example.com", 36106)],
    )
    monkeypatch.setattr(
        vpn_manager.happmeta, "subscription_targets", lambda: [("P", "sub.example.ru", 443)]
    )
    resolved = []
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "resolve_endpoint_ips",
        lambda t, **kw: resolved.append(t) or ["198.51.100.30", "3.3.3.3"],
    )
    calls = []
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "resume_for_happ",
        lambda extra_ips=None, dns=None: calls.append(extra_ips) or ActionResult(True, "ok"),
    )
    monkeypatch.setattr(vpn_manager.killswitch, "mode", lambda: "all")
    result = vpn_manager.guarded_connect(happ, happ.connections()[0])
    assert result.success
    # every balancer member is whitelisted, not just the first one — plus the
    # subscription hosts, so refreshing them still works under the killswitch
    assert [host for _, host, _ in resolved[0]] == [
        "de.example.com",
        "de2.example.com",
        "sub.example.ru",
    ]
    assert calls == [["198.51.100.30", "3.3.3.3"]]


def test_refresh_bar_calls_the_widget_ipc(monkeypatch):
    ran = []
    monkeypatch.setattr(vpn_manager.subprocess, "run", lambda cmd, **k: ran.append(cmd))
    vpn_manager.refresh_bar()
    assert ran == [["omarchy-shell", "-q", vpn_manager.PLUGIN_ID, "refresh"]]


def test_connect_disconnects_other_tunnels(monkeypatch):
    """One tunnel at a time: connecting while another provider is up tears
    the old one down first (two VPNs fight over the default route)."""
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    happ = FakeProvider("Happ", [VPNConnection(name="de", provider="Happ", active=True)])
    patch_menu_env(monkeypatch, [wg, happ], picks=[])
    result = vpn_manager.guarded_connect(wg, wg.connections()[0])
    assert result.success
    assert wg.connected == ["nl"]
    assert happ.disconnected == ["de"]  # torn down before the new connect


def _speed_test_env(monkeypatch, *, measure, ks_on=False, active=(), urls=()):
    """Returns (cfg, notes, emitted) — emitted is every JSON line --check
    printed for the window's card."""
    notes, emitted = [], []
    cfg = config.Config(speed_test_urls=list(urls))
    monkeypatch.setattr(vpn_manager.config, "load_config", lambda: cfg)
    monkeypatch.setattr(vpn_manager, "notify", lambda t, m, urgent=False: notes.append(m))

    class NotesProgress(_FakeProgress):
        def step(self, n, message):
            super().step(n, message)
            notes.append(f"{n}/{self.steps} · {message}" if self.steps else message)

    monkeypatch.setattr(vpn_manager.notifyutil, "Progress", NotesProgress)
    monkeypatch.setattr(vpn_manager, "refresh_bar", lambda: None)
    monkeypatch.setattr(vpn_manager.speedtest, "measure", measure)
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: ks_on)
    monkeypatch.setattr(vpn_manager, "active_connections", lambda: list(active))
    monkeypatch.setattr(vpn_manager, "_emit", emitted.append)
    return cfg, notes, emitted


def _ok(mbps):
    return vpn_manager.speedtest.Measurement(mbps=mbps)


def _err(reason):
    return vpn_manager.speedtest.Measurement(error=reason)


def _result_rows(emitted):
    return [r["text"] for r in emitted[-1]["result"]["rows"]]


def test_speed_test_choices_list_all_presets_and_custom_urls(monkeypatch):
    *_, emitted = _speed_test_env(
        monkeypatch, measure=lambda url, d: _ok(1.0), urls=["http://10.0.0.5/f.bin"]
    )
    vpn_manager.run_check("speed")
    choices = emitted[0]["choices"]
    assert choices[0] == {"key": "all", "label": vpn_manager.SPEED_TEST_ALL_LABEL}
    for s in vpn_manager.speedtest.SERVICES:
        assert {"key": s.name, "label": f"🌐 {s.name}"} in choices
    assert {"key": "http://10.0.0.5/f.bin", "label": "🔗 http://10.0.0.5/f.bin"} in choices


def test_speed_test_single_service_shows_result_in_the_card_not_a_notification(monkeypatch):
    called = []
    svc = vpn_manager.speedtest.SERVICES[0]
    _, notes, emitted = _speed_test_env(
        monkeypatch, measure=lambda url, d: called.append((url, d)) or _ok(123.45)
    )
    result = vpn_manager.run_check("speed", svc.name)
    assert called == [(svc.url, vpn_manager.speedtest.DURATION)]
    assert result.success and result.message == ""
    assert not any("Mbit/s" in m for m in notes)  # only the progress bubble
    rows = _result_rows(emitted)
    assert rows[0] == "Route: direct (no VPN)"
    assert f"{svc.name}: ⬇ 123.5 Mbit/s" in rows
    assert not any(r.startswith("🏆") for r in rows)  # single result — nothing to compare
    assert emitted[-1]["result"]["summary"] == {
        "state": "ok",
        "text": f"{svc.name}: ⬇ 123.5 Mbit/s",
    }


def test_speed_test_all_services_runs_each_in_turn_and_names_fastest(monkeypatch):
    speeds = {
        "http://a": _ok(50.0),
        "http://b": _err("HTTPError: HTTP Error 403"),
        "http://c": _ok(90.0),
    }
    monkeypatch.setattr(
        vpn_manager.speedtest,
        "SERVICES",
        [vpn_manager.speedtest.Service(k.upper(), f"http://{k}") for k in "ab"],
    )
    called = []
    _, notes, emitted = _speed_test_env(
        monkeypatch,
        measure=lambda url, d: called.append((url, d)) or speeds[url],
        urls=["http://c"],
    )
    vpn_manager.run_check("speed", "all")
    d = vpn_manager.SPEED_TEST_ALL_DURATION
    assert called == [("http://a", d), ("http://b", d), ("http://c", d)]
    assert [m.split(":")[0] for m in notes] == ["1/3 · A", "2/3 · B", "3/3 · http"]
    assert [e["step"] for e in emitted if "step" in e] == [1, 2, 3]  # the card's progress
    rows = _result_rows(emitted)
    assert "A: ⬇ 50.0 Mbit/s" in rows
    assert "B: ✗ HTTPError: HTTP Error 403" in rows
    assert "http://c: ⬇ 90.0 Mbit/s" in rows
    assert "🏆 Fastest: http://c (90.0 Mbit/s)" in rows
    states = {r["text"]: r["state"] for r in emitted[-1]["result"]["rows"]}
    assert states["B: ✗ HTTPError: HTTP Error 403"] == "bad"


def test_speed_test_route_row_names_active_vpn(monkeypatch):
    conn = VPNConnection(name="de1", provider="WireGuard", active=True)
    *_, emitted = _speed_test_env(monkeypatch, measure=lambda url, d: _ok(1.0), active=[conn])
    vpn_manager.run_check("speed", "http://x/f")
    assert _result_rows(emitted)[0] == f"Route: {conn.label}"


def test_speed_test_custom_url_is_measured_and_remembered(monkeypatch):
    saved, called = [], []
    _speed_test_env(
        monkeypatch,
        measure=lambda url, d: called.append(url) or _ok(5.0),
        urls=["http://old/a", "http://new/b"],
    )
    monkeypatch.setattr(vpn_manager.config, "save_config", saved.append)
    assert vpn_manager.run_check("speed", "http://new/b").success
    assert called == ["http://new/b"]
    # a remembered URL is a known target: measured, not re-saved
    assert saved == []
    assert vpn_manager.run_check("speed", "http://newer/c").success
    assert saved[0].speed_test_urls == ["http://newer/c", "http://old/a", "http://new/b"]


def test_speed_test_custom_urls_capped_newest_first(monkeypatch):
    saved = []
    old = [f"http://old/{i}" for i in range(vpn_manager.SPEED_TEST_MAX_URLS)]
    _speed_test_env(monkeypatch, measure=lambda url, d: _ok(5.0), urls=old)
    monkeypatch.setattr(vpn_manager.config, "save_config", saved.append)
    assert vpn_manager.run_check("speed", "http://new/x").success
    assert saved[0].speed_test_urls == ["http://new/x", *old[:-1]]


def test_speed_test_custom_url_matching_a_preset_is_not_listed_twice(monkeypatch):
    preset = vpn_manager.speedtest.SERVICES[0]
    called = []
    *_, emitted = _speed_test_env(
        monkeypatch, measure=lambda url, d: called.append(url) or _ok(1.0), urls=[preset.url]
    )
    vpn_manager.run_check("speed")
    assert not any(preset.url in c["key"] for c in emitted[0]["choices"])
    vpn_manager.run_check("speed", "all")
    assert called.count(preset.url) == 1


def test_speed_test_custom_url_rejects_non_http(monkeypatch):
    *_, emitted = _speed_test_env(monkeypatch, measure=lambda url, d: pytest.fail("measured"))
    monkeypatch.setattr(vpn_manager.config, "save_config", lambda cfg: pytest.fail("saved"))
    result = vpn_manager.run_check("speed", "file:///etc/passwd")
    assert not result.success
    assert emitted == [{"error": "Not an http(s) URL: file:///etc/passwd"}]


def test_speed_test_failure_explains_killswitch_without_vpn(monkeypatch):
    *_, emitted = _speed_test_env(monkeypatch, measure=lambda url, d: _err("URLError"), ks_on=True)
    vpn_manager.run_check("speed", "http://x/f")
    assert "killswitch blocks all traffic" in emitted[-1]["error"]


def test_speed_test_failure_without_killswitch_names_the_error_only(monkeypatch):
    *_, emitted = _speed_test_env(monkeypatch, measure=lambda url, d: _err("URLError"))
    vpn_manager.run_check("speed", "http://x/f")
    assert "URLError" in emitted[-1]["error"]
    assert "killswitch" not in emitted[-1]["error"]


def test_dns_leak_server_row_country_alone_is_not_a_leak():
    # a resolver in Russia is no more a leak than one anywhere else — only
    # the ASN/GEO checks against the exit IP decide
    row = vpn_manager._dns_leak_server_row(
        {"ip": "198.51.100.40", "country": "ru", "org": "CloudFlare Inc"}
    )
    assert row == "🇷🇺 198.51.100.40 · CloudFlare Inc"


def test_dns_leak_server_row_clean_no_warning():
    row = vpn_manager._dns_leak_server_row({"ip": "9.9.9.9", "country": "de", "org": "Quad9"})
    label = row
    assert label == "🇩🇪 9.9.9.9 · Quad9"
    assert "⚠RU" not in label


def test_dns_leak_server_row_falls_back_to_asn_without_org():
    row = vpn_manager._dns_leak_server_row(
        {"ip": "1.1.1.1", "country": "au", "asn": "AS13335 CloudFlare Inc"}
    )
    assert "AS13335 CloudFlare Inc" in row


class _FakeProgress:
    """Records a tool's progress notification instead of calling notify-send."""

    last = None

    def __init__(self, title, steps=None):
        self.title, self.steps, self.events = title, steps, []
        _FakeProgress.last = self

    def step(self, n, message):
        self.events.append(("step", n, message))

    def done(self, message):
        self.events.append(("done", message))

    def fail(self, message):
        self.events.append(("fail", message))


def _dns_leak_menu_env(
    monkeypatch, result, active=(), countries=None, ipv6_off=True, second_opinion=None
):
    """Wire run_check("dns")'s collaborators; returns the captured rows list.
    second_opinion: what ipwho.is says about the exit IP's country."""
    monkeypatch.setattr(vpn_manager.ipinfo, "country_of_ip", lambda ip: second_opinion)
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager, "refresh_bar", lambda: None)
    monkeypatch.setattr(vpn_manager.dnsleak, "run", lambda on_step=None: result)
    monkeypatch.setattr(vpn_manager.notifyutil, "Progress", _FakeProgress)
    monkeypatch.setattr(vpn_manager, "active_connections", lambda providers=None: list(active))
    monkeypatch.setattr(vpn_manager.reputation, "country_of", (countries or {}).get)
    monkeypatch.setattr(vpn_manager.ipv6guard, "is_disabled", lambda: ipv6_off)
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "_emit",
        lambda obj: (
            seen.append([r["text"] for r in obj["result"]["rows"]]) if "result" in obj else None
        ),
    )
    return seen


def _leak_result(dns_servers, ip_country="DE", ip_asn=24940):
    return {
        "ip": "1.2.3.4",
        "ip_country": ip_country,
        "ip_asn": ip_asn,
        "dns_servers": dns_servers,
        "conclusion": "",
    }


def _wg(name):
    return VPNConnection(name=name, provider="WireGuard", active=True)


def test_dns_leak_server_row_adds_own_check_tags():
    row = vpn_manager._dns_leak_server_row(
        {"ip": "5.6.7.8", "country": "ru", "asn": "AS12389 Rostelecom"},
        ip_country="DE",
        ip_asn=24940,
    )
    assert row.endswith("  Leaked")


def test_dns_leak_menu_own_verdict_flags_foreign_resolvers(monkeypatch):
    seen = _dns_leak_menu_env(
        monkeypatch,
        _leak_result(
            [
                {"ip": "5.6.7.8", "country": "de", "asn": "AS3320 Telekom"},
                {"ip": "198.51.100.40", "country": "nl", "asn": "AS13335 CloudFlare"},
            ]
        ),
        active=[_wg("de1")],
    )
    vpn_manager.run_check("dns")
    assert "Leaked: 1/2 DNS outside VPN/public resolvers" in seen[0]


def test_dns_leak_menu_own_verdict_clean(monkeypatch):
    seen = _dns_leak_menu_env(
        monkeypatch,
        _leak_result([{"ip": "198.51.100.40", "country": "nl", "asn": "AS13335 CloudFlare"}]),
        active=[_wg("de1")],
    )
    vpn_manager.run_check("dns")
    assert "DNS via VPN or public resolvers" in seen[0]


def test_dns_leak_menu_no_own_verdict_without_exit_ip_data(monkeypatch):
    seen = _dns_leak_menu_env(
        monkeypatch,
        _leak_result([{"ip": "9.9.9.9"}], ip_country="", ip_asn=None),
        active=[_wg("de1")],
    )
    vpn_manager.run_check("dns")
    assert not any("DNS via" in r or "DNS outside" in r for r in seen[0])


def test_dns_leak_menu_warns_when_no_vpn_active(monkeypatch):
    seen = _dns_leak_menu_env(monkeypatch, _leak_result([]), active=[])
    vpn_manager.run_check("dns")
    assert "No VPN active — this is your real IP" in seen[0]


def test_dns_leak_menu_exit_country_matches_connection(monkeypatch):
    seen = _dns_leak_menu_env(
        monkeypatch, _leak_result([]), active=[_wg("de1")], countries={"de1": "DE"}
    )
    vpn_manager.run_check("dns")
    assert "Exit matches de1 🇩🇪" in seen[0]


def test_dns_leak_menu_exit_country_mismatch(monkeypatch):
    seen = _dns_leak_menu_env(
        monkeypatch,
        _leak_result([], ip_country="RU"),
        active=[_wg("de1")],
        countries={"de1": "DE"},
    )
    vpn_manager.run_check("dns")
    assert "Leaked: exit ≠ de1 🇩🇪" in seen[0]


def test_dns_leak_menu_unknown_server_country_just_names_connection(monkeypatch):
    seen = _dns_leak_menu_env(monkeypatch, _leak_result([]), active=[_wg("de1")])
    vpn_manager.run_check("dns")
    assert "VPN: de1" in seen[0]


def test_dns_leak_menu_ipv6_row_warns_only_with_active_vpn(monkeypatch):
    seen = _dns_leak_menu_env(monkeypatch, _leak_result([]), active=[_wg("de1")], ipv6_off=False)
    vpn_manager.run_check("dns")
    assert "Leaked: IPv6 enabled — bypasses the tunnel" in seen[0]

    seen = _dns_leak_menu_env(monkeypatch, _leak_result([]), active=[], ipv6_off=False)
    vpn_manager.run_check("dns")
    assert "IPv6: enabled" in seen[0]


def test_dns_leak_menu_ipv6_disabled_row(monkeypatch):
    seen = _dns_leak_menu_env(monkeypatch, _leak_result([]), active=[_wg("de1")], ipv6_off=True)
    vpn_manager.run_check("dns")
    assert "IPv6: disabled" in seen[0]


def test_dns_leak_test_menu_builds_result_rows(monkeypatch):
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager, "refresh_bar", lambda: None)
    monkeypatch.setattr(vpn_manager, "active_connections", lambda providers=None: [])
    monkeypatch.setattr(vpn_manager.ipv6guard, "is_disabled", lambda: False)
    monkeypatch.setattr(vpn_manager.notifyutil, "Progress", _FakeProgress)
    monkeypatch.setattr(
        vpn_manager.dnsleak,
        "run",
        lambda on_step=None: {
            "ip": "1.2.3.4",
            "ip_country": "DE",
            "dns_servers": [
                {"ip": "198.51.100.40", "country": "ru", "org": "CloudFlare Inc"},
                {"ip": "9.9.9.9", "country": "de", "org": "Quad9"},
            ],
            "conclusion": "DNS may be leaking.",
        },
    )
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "_emit",
        lambda obj: (
            seen.append([r["text"] for r in obj["result"]["rows"]]) if "result" in obj else None
        ),
    )
    result = vpn_manager.run_check("dns")
    assert result.success
    rows = seen[0]
    assert rows[0] == "IP: 1.2.3.4 🇩🇪"
    # CloudFlare egress in RU vs a DE exit -> GEO -> Leaked; Quad9 in DE is fine
    assert any("CloudFlare Inc" in r and r.endswith("Leaked") for r in rows)
    assert any("Quad9" in r and "Leaked" not in r for r in rows)
    assert "bash.ws: DNS may be leaking." in rows
    assert not any(ch in r for r in rows for ch in "⚠✅")  # plain text, no status emoji
    assert "‹ Back" not in rows  # the Tools menu it led back to is gone


def test_dns_leak_test_menu_handles_network_failure(monkeypatch):
    monkeypatch.setattr(vpn_manager.notifyutil, "Progress", _FakeProgress)

    def no_network(on_step=None):
        raise vpn_manager.dnsleak.LeakTestError(1, "[Errno 101] Network is unreachable")

    monkeypatch.setattr(vpn_manager.dnsleak, "run", no_network)
    result = vpn_manager.run_check("dns")
    assert not result.success
    kind, message = _FakeProgress.last.events[-1]
    assert kind == "fail" and "Network is unreachable" in message
    assert "slow" not in message  # the timeout hint is for timeouts only


def test_ip_info_menu_builds_rows(monkeypatch):
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager, "refresh_bar", lambda: None)
    findings = [
        IPFinding(source="ipwho.is", ip="1.2.3.4", country_name="Germany", org="jogcorp"),
        IPFinding(
            source="ip-api.com",
            ip="1.2.3.4",
            country_name="France",
            org="SMARTNET Germany GmbH",
            hosting=True,
            proxy=False,
            mobile=False,
        ),
    ]
    monkeypatch.setattr(vpn_manager.notifyutil, "Progress", _FakeProgress)
    monkeypatch.setattr(
        vpn_manager.reputation, "lookup_self", lambda include_keyed=True, on_step=None: findings
    )
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "_emit",
        lambda obj: (
            seen.append([r["text"] for r in obj["result"]["rows"]]) if "result" in obj else None
        ),
    )
    result = vpn_manager.run_check("ip")
    assert result.success
    rows = seen[0]
    assert rows[0] == "IP: 1.2.3.4"
    assert "ipwho.is: Germany · jogcorp" in rows
    assert "ip-api.com: France · SMARTNET Germany GmbH" in rows
    assert "🏢 Datacenter/Hosting: Yes" in rows
    assert "🕵️ Proxy/VPN detected: No" in rows
    assert "📱 Mobile network: No" in rows
    assert "‹ Back" not in rows


def test_ip_info_menu_handles_no_findings(monkeypatch):
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager.notifyutil, "Progress", _FakeProgress)
    monkeypatch.setattr(
        vpn_manager.reputation, "lookup_self", lambda include_keyed=True, on_step=None: []
    )
    result = vpn_manager.run_check("ip")
    assert not result.success


def test_killswitch_tool_toggle_gathers_targets(monkeypatch, tmp_path):
    """--tool killswitch while off enables 'all' mode with the gathered whitelist."""
    monkeypatch.setattr(vpn_manager.killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: False)
    monkeypatch.setattr(vpn_manager, "_killswitch_all_targets", lambda **kw: (["1.2.3.4"], ["nl"]))
    calls = []
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "set_mode",
        lambda on, **kw: calls.append((on, kw)) or ActionResult(True, "ok"),
    )
    monkeypatch.setattr(vpn_manager.killswitch, "mode", lambda: "off")
    monkeypatch.setattr(vpn_manager, "active_connections", lambda **kw: [])
    vpn_manager.run_tool("killswitch")
    assert calls == [(True, {"extra_ips": ["1.2.3.4"], "ifaces": ["nl"]})]


def test_killswitch_tool_refuses_under_a_networkmanager_vpn(monkeypatch):
    """The kill switch is suspended while NM owns the tunnel (the panel hides
    its badge and the window its button) — --tool must not toggle it either."""
    nm = VPNConnection(name="office", provider="NetworkManager", active=True)
    monkeypatch.setattr(vpn_manager, "active_connections", lambda **kw: [nm])
    monkeypatch.setattr(vpn_manager.killswitch, "set_mode", lambda *a, **kw: pytest.fail("toggled"))
    result = vpn_manager.run_tool("killswitch")
    assert not result.success
    assert "NetworkManager" in result.message


def test_refresh_all_menu_spawns_subs_unconditionally(monkeypatch):
    calls = []
    monkeypatch.setattr(vpn_manager.subprocess, "Popen", lambda cmd, **k: calls.append(cmd) or None)
    result = vpn_manager.refresh_all_menu()
    assert result.success
    flags = [c[2] for c in calls]  # [sys.executable, script_path, flag]
    assert flags == ["--update-subs-force"]  # pings: only the panel's Ping button
    # the forced variant — plain --update-subs would keep the SUB_MAX_AGE
    # gate inside fetch_subscription and no-op on a fresh cache
    assert "--update-subs-force" in flags


def test_clear_caches_menu_removes_only_json_files(tmp_path, monkeypatch):
    cache_dir = tmp_path / "vpn-manager"
    cache_dir.mkdir()
    (cache_dir / "reputation.json").write_text("{}")
    (cache_dir / "happ-ping.json").write_text("{}")
    keep = cache_dir / "not-a-cache.txt"
    keep.write_text("keep me")
    monkeypatch.setattr(vpn_manager, "CACHE_DIR", cache_dir)

    result = vpn_manager.clear_caches_menu()

    assert result.success
    assert not (cache_dir / "reputation.json").exists()
    assert not (cache_dir / "happ-ping.json").exists()
    assert keep.exists()


def test_clear_caches_menu_keeps_subscription_server_lists(tmp_path, monkeypatch):
    """subscription-*.json is the only offline copy of each subscription's
    servers — deleting it empties the Happ menu until a refetch succeeds,
    which a killswitch or a dead network can block indefinitely."""
    cache_dir = tmp_path / "vpn-manager"
    cache_dir.mkdir()
    sub = cache_dir / "subscription-123.json"
    sub.write_text("{}")
    (cache_dir / "happ-ping.json").write_text("{}")
    monkeypatch.setattr(vpn_manager, "CACHE_DIR", cache_dir)
    vpn_manager.clear_caches_menu()
    assert sub.exists()
    assert not (cache_dir / "happ-ping.json").exists()


def test_clear_caches_menu_tolerates_missing_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(vpn_manager, "CACHE_DIR", tmp_path / "does-not-exist")
    result = vpn_manager.clear_caches_menu()
    assert result.success


def _record_ipv6_guard(monkeypatch):
    calls = []
    monkeypatch.setattr(
        vpn_manager.ipv6guard, "disable", lambda: calls.append("disable") or ActionResult(True, "")
    )
    monkeypatch.setattr(
        vpn_manager.ipv6guard, "enable", lambda: calls.append("enable") or ActionResult(True, "")
    )
    return calls


def test_successful_connect_disables_ipv6_even_before_the_tunnel_shows_up(monkeypatch):
    """Happ's keeper reports "connected" on happd's start ack — before xray
    has created happ-xray, while happd's process list may still be the
    cached pre-switch one. Re-probing active_connections() right then saw
    nothing and ENABLED IPv6 on a live tunnel (journal, 17:19:34: xray
    started and disable_ipv6=0 in the same second). A successful connect is
    itself the proof something is up."""
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    patch_menu_env(monkeypatch, [wg], picks=[])
    calls = _record_ipv6_guard(monkeypatch)

    assert vpn_manager.guarded_connect(wg, wg.connections()[0]).success
    assert calls == ["disable"]


def test_failed_connect_still_syncs_ipv6_with_what_is_actually_up(monkeypatch):
    class Failing(FakeProvider):
        def connect(self, conn):
            return ActionResult(False, "nope")

    wg = Failing("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    patch_menu_env(monkeypatch, [wg], picks=[])
    calls = _record_ipv6_guard(monkeypatch)

    assert not vpn_manager.guarded_connect(wg, wg.connections()[0]).success
    assert calls == ["enable"]  # nothing up -> IPv6 back on


def test_dns_leak_exit_row_trusts_name_flag_over_bridge_entry_country(monkeypatch):
    """Whitelist-bypass servers ("🇩🇪 Германия+": every member is a DE+-RU-*
    Russian entry relay) enter in RU and exit in DE by design. The sweep's
    country is the entry IP's, so comparing against it flagged every such
    server as a leak; the provider's flag names the exit country."""
    bridge = "🇩🇪 Германия+"
    seen = _dns_leak_menu_env(
        monkeypatch,
        _leak_result([], ip_country="DE"),
        active=[_wg(bridge)],
        countries={bridge: "RU"},
    )
    vpn_manager.run_check("dns")
    assert f"Exit matches {bridge} 🇩🇪" in seen[0]
    assert not any(r.startswith("Leaked: exit") for r in seen[0])


def test_dns_leak_exit_row_flags_exit_outside_the_name_flag_country(monkeypatch):
    seen = _dns_leak_menu_env(
        monkeypatch,
        _leak_result([], ip_country="RU"),
        active=[_wg("🇩🇪 Германия+")],
        countries={"🇩🇪 Германия+": "RU"},  # entry RU must not excuse a RU exit
    )
    vpn_manager.run_check("dns")
    assert "Leaked: exit ≠ 🇩🇪 Германия+ 🇩🇪" in seen[0]


def test_country_from_name_flag():
    assert vpn_manager._name_flag_country("🇩🇪 Германия+") == "DE"
    assert vpn_manager._name_flag_country("Fast 🇳🇱 NL-2") == "NL"  # not only leading
    assert vpn_manager._name_flag_country("Germany #41294") is None
    assert vpn_manager._name_flag_country("🇩 broken") is None  # lone regional indicator


def test_dns_leak_exit_row_eu_flag_accepts_any_member_state(monkeypatch):
    # 🇪🇺 is not a country: 13 real servers carry it and exit in NL/DE/EE...
    cases = (("NL", "Exit matches 🇪🇺 Europe 🇪🇺"), ("RU", "Leaked: exit ≠ 🇪🇺 Europe 🇪🇺"))
    for exit_cc, row in cases:
        seen = _dns_leak_menu_env(
            monkeypatch, _leak_result([], ip_country=exit_cc), active=[_wg("🇪🇺 Europe")]
        )
        vpn_manager.run_check("dns")
        assert row in seen[0], exit_cc


def test_dns_leak_exit_row_second_geo_opinion_clears_a_geo_db_mismatch(monkeypatch):
    """Poland 1: bash.ws geolocated its exit 192.144.78.10 (leased IPbnb
    block) to KR, ipwho.is to PL/Warsaw, ip-api to FR — while the resolvers
    were Cloudflare's Polish PoP. One geo DB's opinion isn't a leak."""
    seen = _dns_leak_menu_env(
        monkeypatch,
        _leak_result([], ip_country="KR"),
        active=[_wg("🇵🇱 Польша 1")],
        second_opinion="PL",
    )
    vpn_manager.run_check("dns")
    assert "Exit matches 🇵🇱 Польша 1 🇵🇱 · bash.ws: 🇰🇷" in seen[0]


def test_dns_leak_exit_row_still_leaks_when_second_opinion_disagrees_too(monkeypatch):
    for second in ("KR", None):
        seen = _dns_leak_menu_env(
            monkeypatch,
            _leak_result([], ip_country="KR"),
            active=[_wg("🇵🇱 Польша 1")],
            second_opinion=second,
        )
        vpn_manager.run_check("dns")
        assert "Leaked: exit ≠ 🇵🇱 Польша 1 🇵🇱" in seen[0], second


def test_dns_leak_menu_shows_each_step_then_done(monkeypatch):
    def run(on_step=None):
        for n, label in enumerate(vpn_manager.dnsleak.STEPS, 1):
            on_step(n, label)
        return _leak_result([])

    seen = _dns_leak_menu_env(monkeypatch, None, active=[_wg("de1")])
    monkeypatch.setattr(vpn_manager.dnsleak, "run", run)
    vpn_manager.run_check("dns")
    events = _FakeProgress.last.events
    assert [e[1] for e in events if e[0] == "step"] == [1, 2, 3]
    assert events[-1][0] == "done"
    assert seen  # the result follows the steps


def test_dns_leak_menu_failure_names_the_step_and_reason(monkeypatch):
    def run(on_step=None):
        on_step(1, vpn_manager.dnsleak.STEPS[0])
        raise vpn_manager.dnsleak.LeakTestError(1, "The handshake operation timed out")

    seen = _dns_leak_menu_env(monkeypatch, None, active=[_wg("de1")])
    monkeypatch.setattr(vpn_manager.dnsleak, "run", run)
    result = vpn_manager.run_check("dns")
    kind, message = _FakeProgress.last.events[-1]
    assert kind == "fail"
    assert "1/3" in message and "handshake operation timed out" in message
    assert "slow" in message  # timeout hint: a slow or blocking exit, not "no network"
    assert not result.success and result.message == ""  # notified once, not twice
    assert seen == []  # no result, an error line


def test_speed_test_all_failed_ends_progress_with_the_reason(monkeypatch):
    monkeypatch.setattr(
        vpn_manager.speedtest,
        "SERVICES",
        [vpn_manager.speedtest.Service(k.upper(), f"http://{k}") for k in "ab"],
    )
    _speed_test_env(monkeypatch, measure=lambda url, d: _err("URLError: timed out"))
    vpn_manager.run_check("speed", "all")
    kind, message = _FakeProgress.last.events[-1]
    assert kind == "fail" and "URLError: timed out" in message


def test_speed_test_success_ends_progress_with_done(monkeypatch):
    _speed_test_env(monkeypatch, measure=lambda url, d: _ok(9.0))
    vpn_manager.run_check("speed", "http://a/f")
    assert _FakeProgress.last.events[-1][0] == "done"


def _ip_info_env(monkeypatch, lookup):
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager.notifyutil, "Progress", _FakeProgress)
    monkeypatch.setattr(vpn_manager.reputation, "lookup_self", lookup)
    monkeypatch.setattr(vpn_manager, "_emit", lambda obj: None)


def test_ip_info_failure_says_the_own_ip_could_not_be_detected(monkeypatch):
    def lookup(include_keyed=True, on_step=None):
        on_step(1, "detecting your public IP")
        return []

    _ip_info_env(monkeypatch, lookup)
    result = vpn_manager.run_check("ip")
    kind, message = _FakeProgress.last.events[-1]
    assert kind == "fail" and "public IP" in message
    assert not result.success and result.message == ""


def test_ip_info_failure_says_no_source_answered(monkeypatch):
    def lookup(include_keyed=True, on_step=None):
        on_step(1, "detecting your public IP")
        on_step(2, "asking 2 IP sources")
        return []

    _ip_info_env(monkeypatch, lookup)
    vpn_manager.run_check("ip")
    kind, message = _FakeProgress.last.events[-1]
    assert kind == "fail" and "no IP source answered" in message


def test_failure_hint_blames_the_killswitch_when_no_vpn_is_up(monkeypatch):
    """killswitch_mode "all" keeps the rules after a disconnect: a tool run
    then times out by design, and "the VPN exit may be slow" misleads."""
    monkeypatch.setattr(vpn_manager, "active_connections", list)
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: True)
    assert "killswitch blocks all traffic" in vpn_manager._failure_hint("timed out")


def test_failure_hint_blames_a_slow_exit_for_a_timeout_through_a_tunnel(monkeypatch):
    up = VPNConnection(name="de", provider="Happ", active=True)
    monkeypatch.setattr(vpn_manager, "active_connections", lambda: [up])
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: True)
    assert "exit may be slow" in vpn_manager._failure_hint("The read operation timed out")
    assert vpn_manager._failure_hint("HTTP 502") == ""


def test_failure_hint_without_vpn_and_killswitch_adds_nothing_to_a_plain_error(monkeypatch):
    monkeypatch.setattr(vpn_manager, "active_connections", list)
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: False)
    assert vpn_manager._failure_hint("HTTP 502") == ""


def _fake_report_data(monkeypatch):
    monkeypatch.setattr(
        vpn_manager.happmeta,
        "providers",
        lambda: {
            "1": {"name": "Unlock VPN", "url": "https://x/1"},
            "2": {"name": "OK", "url": "https://x/2"},
            "0": {"name": "routing only", "url": None},
        },
    )
    monkeypatch.setattr(
        vpn_manager.happmeta,
        "all_servers",
        lambda allow_fetch=True: [
            {"name": "DE", "provider_id": "1"},
            {"name": "NL", "provider_id": "1"},
            {"name": "PL", "provider_id": "2"},
        ],
    )
    monkeypatch.setattr(
        vpn_manager.happmeta,
        "provider_ping_summary",
        lambda names: "✓ 2/2 · ⌀45ms" if names == ["1\tDE", "1\tNL"] else None,
    )
    monkeypatch.setattr(
        vpn_manager.happmeta,
        "subscription_info",
        lambda sub_id: (
            {"download": 6.5 * 2**30, "total": 0, "expire": 1797232846} if sub_id == "1" else None
        ),
    )


def test_subscription_report_lists_ping_and_traffic_per_provider(monkeypatch):
    _fake_report_data(monkeypatch)
    title, body = vpn_manager.subscription_report({})
    assert title == "Happ — subscriptions updated"
    assert body.splitlines() == [
        "Unlock VPN: ✓ 2/2 · ⌀45ms · 6.5 GB / ∞ · until 14.12.2026",
        "OK: 1 servers, no ping yet",
    ]


def test_subscription_report_marks_what_did_not_update(monkeypatch):
    _fake_report_data(monkeypatch)
    title, body = vpn_manager.subscription_report({"OK": "timed out"})
    assert title == "Happ — 1 subscription(s) not updated"
    assert "⚠️ OK: 1 servers, no ping yet\n    not updated: timed out" in body


def test_manual_subscription_refresh_always_reports(monkeypatch):
    """--update-subs-force runs detached from the menu: without a
    notification a provider that didn't answer looked refreshed."""
    monkeypatch.setattr(vpn_manager.sys, "argv", ["vpn_manager.py", "--update-subs-force"])
    monkeypatch.setattr(vpn_manager.happmeta, "update_subscriptions", lambda force: {})
    monkeypatch.setattr(vpn_manager, "subscription_report", lambda failed: ("T", "B"))
    sent = []
    monkeypatch.setattr(vpn_manager, "notify", lambda title, msg, **kw: sent.append((title, msg)))
    vpn_manager.main()
    assert sent == [("T", "B")]


def _ks_env(monkeypatch, tmp_path, *, lockdown=True, enabled=True):
    """Kill switch in "all" mode with one resolver; returns the dns arg of every rules load."""
    monkeypatch.setattr(vpn_manager.killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    cfg = vpn_manager.killswitch.config.load_config()
    cfg.killswitch_mode = "all"
    cfg.killswitch_lockdown = lockdown
    vpn_manager.killswitch.config.save_config(cfg)
    monkeypatch.setattr(vpn_manager.killswitch, "system_resolvers", lambda: ["192.168.1.1"])
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: enabled)
    monkeypatch.setattr(vpn_manager, "_killswitch_all_targets", lambda **kw: (["1.2.3.4"], ["nl"]))
    loads = []
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "enable",
        lambda **kw: loads.append(kw["dns"]) or ActionResult(True, "on"),
    )
    monkeypatch.setattr(vpn_manager, "_sync_ipv6_guard", lambda: None)
    return loads


def test_dns_hole_closes_when_the_old_tunnel_wont_go_down(monkeypatch, tmp_path):
    """Review: the early `return down` skipped the close — port 53 stayed open."""
    loads = _ks_env(monkeypatch, tmp_path)

    class Stuck(FakeProvider):
        def disconnect(self, conn):
            return ActionResult(False, "busy")

    old = Stuck("OpenVPN", [VPNConnection(name="old", provider="OpenVPN", active=True)])
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [old, wg])
    assert not vpn_manager.guarded_connect(wg, wg.connections()[0]).success
    assert wg.connected == []
    assert loads[-1] == []  # strict again


def test_dns_hole_closes_when_connect_raises(monkeypatch, tmp_path):
    loads = _ks_env(monkeypatch, tmp_path)

    class Crashing(FakeProvider):
        def connect(self, conn):
            raise OSError("wg-quick vanished")

    wg = Crashing("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg])
    with pytest.raises(OSError):
        vpn_manager.guarded_connect(wg, wg.connections()[0])
    assert loads[-1] == []


def test_dns_hole_closes_even_if_the_second_load_failed(monkeypatch, tmp_path):
    """Review: a failed re-apply (fresh IPs) left the first load's hole in place."""
    _ks_env(monkeypatch, tmp_path)
    ips = iter([(["1.2.3.4"], ["nl"]), (["5.6.7.8"], ["nl"])])  # cached, then fresh
    monkeypatch.setattr(vpn_manager, "_killswitch_all_targets", lambda **kw: next(ips))
    results = iter([ActionResult(True, "on"), ActionResult(False, "nft: error"), None])
    loads = []

    def enable(**kw):
        loads.append(kw["dns"])
        return next(results) or ActionResult(True, "on")

    monkeypatch.setattr(vpn_manager.killswitch, "enable", enable)
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg])
    vpn_manager.guarded_connect(wg, wg.connections()[0])
    assert loads == [["192.168.1.1"], ["192.168.1.1"], []]


def test_failed_connect_without_lockdown_closes_the_hole_if_rules_stay(monkeypatch, tmp_path):
    """Review: Lockdown off + something still looking up — the release declines,
    and the hole must be closed instead of left open."""
    loads = _ks_env(monkeypatch, tmp_path, lockdown=False)
    still_up = VPNConnection(name="happ", provider="Happ", active=True)
    monkeypatch.setattr(vpn_manager, "active_connections", lambda providers=None: [still_up])
    monkeypatch.setattr(vpn_manager.happ_provider, "_invalidate_procs_cache", lambda: None)

    class Broken(FakeProvider):
        def connect(self, conn):
            return ActionResult(False, "handshake timed out")

    wg = Broken("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg])
    monkeypatch.setattr(vpn_manager, "_disconnect_all", lambda: ActionResult(True, ""))
    vpn_manager.guarded_connect(wg, wg.connections()[0])
    assert loads[-1] == []


def test_an_enabled_kill_switch_opens_the_hole_before_any_lookup(monkeypatch, tmp_path):
    """The old rules block DNS: the first load uses last-known IPs (no lookup),
    then one resolve runs with DNS open — not two waits of RESOLVE_TIMEOUT."""
    _ks_env(monkeypatch, tmp_path)
    order = []
    monkeypatch.setattr(
        vpn_manager,
        "_killswitch_all_targets",
        lambda cached_only=False: (
            order.append("cached" if cached_only else "resolve") or (["1.2.3.4"], ["nl"])
        ),
    )
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "enable",
        lambda **kw: order.append(f"rules dns={bool(kw['dns'])}") or ActionResult(True, "on"),
    )
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg])
    assert vpn_manager.guarded_connect(wg, wg.connections()[0]).success
    assert order == ["cached", "rules dns=True", "resolve", "rules dns=False"]


@pytest.mark.parametrize("appears", [True, False], ids=["tun-up", "never"])
def test_openvpn_keeps_the_dns_hole_until_its_tun_exists(monkeypatch, tmp_path, appears):
    """`openvpn --daemon` returns before it resolves `remote`: the hole closes
    only once its tun device shows up — or the wait runs out."""
    order = []
    _ks_env(monkeypatch, tmp_path, enabled=False)
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "enable",
        lambda **kw: order.append(f"rules dns={bool(kw['dns'])}") or ActionResult(True, "on"),
    )
    polls = iter([set(), set(), {"tun0"} if appears else set()])
    monkeypatch.setattr(
        vpn_manager,
        "_tun_interfaces",
        lambda: order.append("poll") or next(polls, {"tun0"} if appears else set()),
    )
    monkeypatch.setattr(vpn_manager, "OPENVPN_TUN_WAIT", 0.3)
    monkeypatch.setattr(vpn_manager.time, "sleep", lambda s: None)
    ovpn = FakeProvider("OpenVPN", [VPNConnection(name="de", provider="OpenVPN", active=False)])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [ovpn])
    assert vpn_manager.guarded_connect(ovpn, ovpn.connections()[0]).success
    assert order[0] == "rules dns=True"
    assert order[-1] == "rules dns=False"
    assert order.count("poll") >= 3  # before the connect + polled until tun0 / timeout


def test_a_switch_leaves_the_ping_sweep_alone():
    """Its xray probes don't depend on the connection being switched."""
    assert "--ping-now" not in vpn_manager.CHECK_FLAGS


def test_tool_flag_runs_the_tools_action(monkeypatch):
    """--tool KEY (the app window's Tools buttons) runs the same TOOLS action
    the old 🛠 Tools submenu did."""
    ran = []
    tools = [
        (k, label, lambda k=k: ran.append(k) or ActionResult(True, ""))
        for k, label, _ in vpn_manager.TOOLS
    ]
    monkeypatch.setattr(vpn_manager, "TOOLS", tools)
    vpn_manager.run_tool("speed_test")
    assert ran == ["speed_test"]


def test_dns_check_card_summary_names_the_first_leak(monkeypatch):
    """The window's card leads with a verdict: the first leaking row, else
    our resolver verdict — and never "ok" without data to judge."""
    _dns_leak_menu_env(
        monkeypatch,
        _leak_result([{"ip": "5.6.7.8", "country": "de", "asn": "AS3320 Telekom"}]),
        active=[_wg("de1")],
    )
    emitted = []
    monkeypatch.setattr(vpn_manager, "_emit", emitted.append)
    vpn_manager.run_check("dns")
    summary = emitted[-1]["result"]["summary"]
    assert summary["state"] == "bad"
    assert summary["text"].startswith("Leaked")

    _dns_leak_menu_env(monkeypatch, _leak_result([], ip_country="", ip_asn=None), active=[])
    emitted.clear()
    monkeypatch.setattr(vpn_manager, "_emit", emitted.append)
    vpn_manager.run_check("dns")
    assert emitted[-1]["result"]["summary"]["state"] == "unknown"


def test_a_cancelled_check_tells_the_card_and_closes_the_bubble(monkeypatch):
    def run(on_step=None):
        raise vpn_manager.CheckCancelled

    _dns_leak_menu_env(monkeypatch, None, active=[_wg("de1")])
    monkeypatch.setattr(vpn_manager.dnsleak, "run", run)
    emitted = []
    monkeypatch.setattr(vpn_manager, "_emit", emitted.append)
    assert not vpn_manager.run_check("dns").success
    assert emitted == [{"error": vpn_manager.CANCELLED}]
    assert _FakeProgress.last.events[-1] == ("done", vpn_manager.CANCELLED)
