"""The panel's server list (--servers) and its connect/disconnect actions."""

import time

import pytest

import config
import happmeta
import vpn_manager
from providers.base import ActionResult, VPNConnection


class FakeProvider:
    def __init__(self, name, conns):
        self.name = name
        self._conns = conns
        self.connected, self.disconnected = [], []

    def connections(self):
        return self._conns

    def connect(self, conn):
        self.connected.append(conn)
        return ActionResult(True, f"connected {conn.name}")

    def disconnect(self, conn):
        self.disconnected.append(conn)
        return ActionResult(True, f"disconnected {conn.name}")


@pytest.fixture
def env(monkeypatch, tmp_path):
    """Pings from a fake cache; no background sweeps or subscription fetches."""
    pings = {}
    monkeypatch.setattr(happmeta, "_read_pings", lambda: pings)
    monkeypatch.setattr(happmeta, "request_subscription_update", lambda: None)
    monkeypatch.setattr(happmeta, "providers", dict)
    monkeypatch.setattr(vpn_manager.config, "load_config", config.Config)
    return pings


def test_ping_status_fresh_stale_none(env):
    now = time.time()
    env["a"] = {"ms": 42.0, "at": now}
    env["b"] = {"ms": 42.0, "at": now - happmeta.PING_MAX_AGE - 1}
    env["c"] = {"ms": None, "at": now}
    assert happmeta.ping_status("a") == ("fresh", 42.0)
    assert happmeta.ping_status("b") == ("stale", 42.0)
    assert happmeta.ping_status("c") == ("fresh", None)
    assert happmeta.ping_status("nope") == ("none", None)


@pytest.mark.parametrize(
    ("entry", "ping", "stale"),
    [
        ({"ms": 46.6, "fresh": True}, "47 ms", False),
        ({"ms": 46.6, "fresh": False}, "~47 ms", True),  # older than PING_MAX_AGE
        ({"ms": None, "fresh": True}, "timeout", False),
        ({"ms": None, "fresh": False}, "timeout", True),  # an old timeout is just dimmed
        (None, "", False),  # never swept: say nothing
    ],
)
def test_server_row_ping(env, entry, ping, stale):
    if entry is not None:
        age = 0 if entry["fresh"] else happmeta.PING_MAX_AGE + 1
        env["🇵🇱 Польша"] = {"ms": entry["ms"], "at": time.time() - age}
    row = vpn_manager._server_row({"name": "🇵🇱 Польша", "active": False, "protocol": "vless"})
    assert (row["ping"], row["stale"]) == (ping, stale)
    assert row["country"] == "pl"  # the filter finds Russian names by code


def test_server_list_groups_happ_per_subscription_and_other_providers(env, monkeypatch):
    env["15\t🇩🇪 DE"] = {"ms": 40.0, "at": time.time()}  # happmeta.ping_key()
    env["15\t🇳🇱 NL"] = {"ms": 60.0, "at": time.time()}
    happ = FakeProvider("Happ", [])
    wg = FakeProvider("WireGuard", [VPNConnection(name="home", provider="WireGuard", active=True)])
    empty = FakeProvider("OpenVPN", [])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [happ, wg, empty])
    monkeypatch.setattr(
        vpn_manager,
        "happ_server_groups",
        lambda provider: (
            [],
            {
                "Provider A": [
                    {"name": "🇩🇪 DE", "active": True, "provider_id": "15", "protocol": "vless"},
                    {"name": "🇳🇱 NL", "active": False, "provider_id": "15", "protocol": "ss"},
                ]
            },
        ),
    )
    listing = vpn_manager.server_list()
    groups = listing["groups"]
    assert [(g["provider"], g["title"], g["active"]) for g in groups] == [
        ("Happ", "Provider A", True),
        ("WireGuard", "WireGuard", True),
    ]  # a provider with nothing to show has no group…
    # …but is still a protocol of the window's tree/tabs/sidebar
    assert listing["providers"] == [
        {
            "name": "Happ",
            "importer": None,
            "manage": False,
            "autostart": False,
            "total": 2,
            "active": True,
        },
        {
            "name": "WireGuard",
            "importer": "file",
            "manage": True,
            "autostart": True,
            "total": 1,
            "active": True,
        },
        {
            "name": "OpenVPN",
            "importer": "file",
            "manage": True,
            "autostart": True,
            "total": 0,
            "active": False,
        },
    ]
    assert listing["layout"] == "tree"
    sub_a = groups[0]
    assert sub_a["subscription_id"] == "15"
    assert sub_a["summary"] == "✓ 2/2 · 60 ms"  # median of reachable
    assert [(r["name"], r["ping"], r["active"]) for r in sub_a["servers"]] == [
        ("🇩🇪 DE", "40 ms", True),
        ("🇳🇱 NL", "60 ms", False),
    ]


def test_server_list_hides_hidden_providers_and_survives_a_broken_one(env, monkeypatch):
    class Broken(FakeProvider):
        def connections(self):
            raise OSError("boom")

    wg = FakeProvider("WireGuard", [VPNConnection(name="home", provider="WireGuard", active=False)])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [Broken("OpenVPN", []), wg])
    monkeypatch.setattr(vpn_manager.logutil, "log", lambda msg: None)
    monkeypatch.setattr(
        vpn_manager.config, "load_config", lambda: config.Config(providers={"wireguard": False})
    )
    assert vpn_manager.server_list()["groups"] == []


def _guarded(monkeypatch):
    calls = []
    monkeypatch.setattr(
        vpn_manager,
        "guarded_connect",
        lambda p, c: calls.append(("up", p.name, c)) or ActionResult(True, "ok"),
    )
    monkeypatch.setattr(
        vpn_manager,
        "guarded_disconnect",
        lambda p, c: calls.append(("down", p.name, c)) or ActionResult(True, "ok"),
    )
    return calls


def test_panel_connect_resolves_a_provider_hidden_from_the_server_list(monkeypatch):
    """Hidden in Locations ≠ unregistered: connect still finds the provider."""
    calls = _guarded(monkeypatch)
    home = VPNConnection(name="home", provider="WireGuard", active=False)
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [FakeProvider("WireGuard", [home])])
    monkeypatch.setattr(
        vpn_manager.config,
        "load_config",
        lambda: config.Config(providers={"wireguard": False}),
    )
    assert vpn_manager.server_list()["groups"] == []
    assert vpn_manager.panel_connect("WireGuard", "home").success
    assert calls == [("up", "WireGuard", home)]


def test_panel_connect_happ_carries_the_subscription(monkeypatch):
    calls = _guarded(monkeypatch)
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [FakeProvider("Happ", [])])
    monkeypatch.setattr(happmeta, "providers", lambda: {"15": {"name": "Provider A", "url": "u"}})
    assert vpn_manager.panel_connect("Happ", "🇩🇪 DE", "15").success
    _, provider, conn = calls[0]
    assert (provider, conn.name, conn.subscription_id, conn.subscription_name) == (
        "Happ",
        "🇩🇪 DE",
        "15",
        "Provider A",
    )


def test_panel_connect_other_provider_uses_its_connection(monkeypatch):
    calls = _guarded(monkeypatch)
    home = VPNConnection(name="home", provider="WireGuard", active=False, config_path="/x")
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [FakeProvider("WireGuard", [home])])
    assert vpn_manager.panel_connect("WireGuard", "home").success
    assert calls == [("up", "WireGuard", home)]
    assert not vpn_manager.panel_connect("WireGuard", "gone").success
    assert not vpn_manager.panel_connect("Nope", "home").success


def test_panel_disconnect_matches_by_name_or_any_happ(monkeypatch):
    calls = _guarded(monkeypatch)
    happ_conn = VPNConnection(name="Germany", provider="Happ", active=True)  # GUI name, no emoji
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [FakeProvider("Happ", [happ_conn])])
    assert vpn_manager.panel_disconnect("Happ", "🇩🇪 Germany").success
    assert calls == [("down", "Happ", happ_conn)]
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [FakeProvider("WireGuard", [])])
    assert not vpn_manager.panel_disconnect("WireGuard", "home").success


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["--connect", "Happ", "🇩🇪 DE", "15"], ("connect", ("Happ", "🇩🇪 DE", "15"))),
        (["--connect", "WireGuard", "home"], ("connect", ("WireGuard", "home"))),
        (["--disconnect", "WireGuard", "home"], ("disconnect", ("WireGuard", "home"))),
    ],
)
def test_panel_cli_connect_disconnect(monkeypatch, argv, expected):
    seen, reported = [], []
    monkeypatch.setattr(vpn_manager.sys, "argv", ["vpn_manager.py", *argv])
    monkeypatch.setattr(
        vpn_manager,
        "panel_connect",
        lambda *a: seen.append(("connect", a)) or ActionResult(True, "up"),
    )
    monkeypatch.setattr(
        vpn_manager,
        "panel_disconnect",
        lambda *a: seen.append(("disconnect", a)) or ActionResult(True, "down"),
    )
    monkeypatch.setattr(vpn_manager, "_report", reported.append)
    vpn_manager.main()
    assert seen == [expected]
    assert len(reported) == 1


def test_panel_cli_connect_rejects_wrong_arity(monkeypatch):
    monkeypatch.setattr(vpn_manager.sys, "argv", ["vpn_manager.py", "--connect", "Happ"])
    with pytest.raises(SystemExit):
        vpn_manager.main()


def test_server_row_marks_a_ping_skipped_under_the_killswitch(env):
    env["home"] = {"ms": None, "at": time.time(), "skipped": True}
    row = vpn_manager._server_row({"name": "home", "active": False})
    assert (row["ping"], row["ping_ms"]) == ("—", None)
    assert happmeta.ping_mark("home") == ""


def test_server_list_says_why_a_subscription_sent_no_servers(env, monkeypatch):
    """A device-limited panel answers stub rows: its group says so in the
    panel's words (the old Happ menu's "⚠️ <provider>: …" row)."""
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [FakeProvider("Happ", [])])
    monkeypatch.setattr(
        vpn_manager,
        "happ_server_groups",
        lambda provider: ([], {"OK": [{"name": "🇩🇪 DE", "active": False, "provider_id": "8"}]}),
    )
    monkeypatch.setattr(
        happmeta, "providers", lambda: {"7": {"name": "Provider C"}, "8": {"name": "OK"}}
    )
    monkeypatch.setattr(
        happmeta,
        "subscription_rejection",
        lambda sub_id: ["⚠️ Достигнут лимит устройств: 4"] if sub_id in ("7", "8") else [],
    )
    titles = [g["title"] for g in vpn_manager.server_list()["groups"]]
    # OK still has (last known) servers: no extra group for it
    assert titles == ["OK", "Provider C · ⚠ Достигнут лимит устройств: 4"]


def test_server_list_never_blocks_on_the_network(env, monkeypatch):
    """The window/panel list reads subscriptions cache-only and refreshes them
    in the background — allow_fetch=True fetches every stale subscription
    synchronously (measured 15 s against a real stale cache, see CLAUDE.md)."""
    calls = []
    monkeypatch.setattr(
        happmeta, "request_subscription_update", lambda: calls.append("background refresh")
    )

    def fake_all_servers(allow_fetch=True):
        assert not allow_fetch, "the server list must never fetch subscriptions synchronously"
        return []

    monkeypatch.setattr(happmeta, "all_servers", fake_all_servers)
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [FakeProvider("Happ", [])])
    vpn_manager.server_list()
    assert calls == ["background refresh"]


@pytest.mark.parametrize(("captured", "hint"), [(False, True), (True, False)])
def test_server_list_explains_an_empty_happ_without_captured_headers(
    env, monkeypatch, captured, hint
):
    """No servers at all with Happ's default headers: the panel may need the
    device's own (the old menu's "No servers" row) — said once, as a group."""
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [FakeProvider("Happ", [])])
    monkeypatch.setattr(vpn_manager, "happ_server_groups", lambda provider: ([], {}))
    monkeypatch.setattr(happmeta, "has_headers", lambda: captured)
    titles = [g["title"] for g in vpn_manager.server_list()["groups"]]
    assert titles == ([vpn_manager.HAPP_NO_HEADERS_TITLE] if hint else [])
