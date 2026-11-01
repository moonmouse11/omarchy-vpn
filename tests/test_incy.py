"""INCY provider: read-only incy.db listing."""

import json
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace

import providers.incy as incy_mod
import vpn_manager
from providers.common.types import ActionResult, VPNConnection
from providers.happd.incy import IncyProvider, incy_server_groups


def test_load_connections_from_incy_db(tmp_path, monkeypatch):
    db = tmp_path / "incy.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE subscriptions (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, customName TEXT,
            profileName TEXT, isEnabled INTEGER NOT NULL DEFAULT 1,
            orderIndex INTEGER DEFAULT 0
        );
        CREATE TABLE servers (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, subscriptionId TEXT,
            isActive INTEGER NOT NULL DEFAULT 0, orderIndex INTEGER DEFAULT 0,
            address TEXT, port INTEGER, proxyProtocol TEXT, uuid TEXT,
            encryption TEXT, network TEXT, security TEXT
        );
        INSERT INTO subscriptions VALUES ('sub1', 'Prov', '', 'WireCat VPN', 1, 0);
        INSERT INTO servers VALUES ('s1', '🇩🇪 DE', 'sub1', 1, 0,
            '1.1.1.1', 443, 'vless', 'u', 'none', 'tcp', 'tls');
        """
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr(incy_mod, "INCY_DB", db)
    provider = IncyProvider()
    conns = provider.connections()
    assert len(conns) == 1
    assert conns[0].name == "🇩🇪 DE"
    assert conns[0].subscription_id == "sub1"
    assert conns[0].subscription_name == "WireCat VPN"
    assert conns[0].active is False  # DB selection is not a live tunnel.

    _all, groups = incy_server_groups(provider)
    assert "WireCat VPN" in groups
    assert groups["WireCat VPN"][0]["provider_id"] == "sub1"


def test_active_connections_loads_active_rows_when_link_up_without_keeper(tmp_path, monkeypatch):
    import providers.happd.incy as incy_impl

    db = tmp_path / "incy.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE subscriptions (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, customName TEXT,
            profileName TEXT, isEnabled INTEGER NOT NULL DEFAULT 1,
            orderIndex INTEGER DEFAULT 0
        );
        CREATE TABLE servers (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, subscriptionId TEXT,
            isActive INTEGER NOT NULL DEFAULT 0, orderIndex INTEGER DEFAULT 0,
            address TEXT, port INTEGER, proxyProtocol TEXT, uuid TEXT,
            encryption TEXT, network TEXT, security TEXT
        );
        INSERT INTO subscriptions VALUES ('sub1', 'Prov', '', 'WireCat VPN', 1, 0);
        INSERT INTO servers VALUES ('s1', '🇩🇪 DE', 'sub1', 1, 0,
            '1.1.1.1', 443, 'vless', 'u', 'none', 'tcp', 'tls');
        """
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr(incy_mod, "INCY_DB", db)
    monkeypatch.setattr(incy_mod, "KEEPER_STATE", tmp_path / "missing-keeper.json")
    monkeypatch.setattr(incy_impl, "_incy_link_up", lambda: True)

    active = IncyProvider().active_connections()
    assert len(active) == 1 and active[0].name == "🇩🇪 DE"


def test_active_connections_keeper_resolves_sub_name_without_full_list(tmp_path, monkeypatch):
    import providers.happd.incy as incy_impl

    db = tmp_path / "incy.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE subscriptions (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, customName TEXT,
            profileName TEXT, isEnabled INTEGER NOT NULL DEFAULT 1,
            orderIndex INTEGER DEFAULT 0
        );
        CREATE TABLE servers (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, subscriptionId TEXT,
            isActive INTEGER NOT NULL DEFAULT 0, orderIndex INTEGER DEFAULT 0,
            address TEXT, port INTEGER, proxyProtocol TEXT, uuid TEXT,
            encryption TEXT, network TEXT, security TEXT
        );
        INSERT INTO subscriptions VALUES ('sub1', 'Prov', '', 'WireCat VPN', 1, 0);
        INSERT INTO servers VALUES ('s1', '🇩🇪 DE', 'sub1', 1, 0,
            '1.1.1.1', 443, 'vless', 'u', 'none', 'tcp', 'tls');
        """
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr(incy_mod, "INCY_DB", db)
    keeper = tmp_path / "keeper.json"
    keeper.write_text(json.dumps({"status": "connected", "server": "🇩🇪 DE", "provider_id": "sub1"}))
    monkeypatch.setattr(incy_mod, "KEEPER_STATE", keeper)
    monkeypatch.setattr(incy_impl, "_live_worker", lambda _s: True)

    load_calls = {"n": 0}
    real_load = incy_impl._load_connections

    def counting_load():
        load_calls["n"] += 1
        return real_load()

    monkeypatch.setattr(incy_impl, "_load_connections", counting_load)

    active = IncyProvider().active_connections()
    assert load_calls["n"] == 0
    assert len(active) == 1
    assert active[0].subscription_name == "WireCat VPN"
    assert active[0].subscription_id == "sub1"


def test_connect_refuses_when_incy_not_installed(monkeypatch):
    monkeypatch.setattr(incy_mod, "incy_installed", lambda: False)
    from providers.common.types import VPNConnection

    r = IncyProvider().connect(VPNConnection("x", "INCY", False))
    assert not r.success
    assert "not found" in r.message.lower() or "not installed" in r.message.lower()


def test_fetch_incy_subscription_cache(tmp_path, monkeypatch):
    from incy import subscriptions as incy_subs

    _patch_sub_cache(monkeypatch, tmp_path)
    monkeypatch.setattr(
        incy_subs,
        "fetch_subscription_to_cache",
        lambda path, url, headers, **kw: ([{"remarks": "S1", "outbounds": [{}]}], None),
    )
    monkeypatch.setattr(incy_subs, "subscription_url", lambda _sid: "https://example/sub")
    servers, err = incy_subs.fetch_servers("sub1")
    assert err is None
    assert servers[0]["remarks"] == "S1"


def test_incy_runtime_config_is_tun_only(tmp_path, monkeypatch):
    from incy.config import build_incy_runtime_config

    cfg = {
        "remarks": "x",
        "outbounds": [{"protocol": "vless", "tag": "proxy", "settings": {}}],
    }
    runtime = build_incy_runtime_config(cfg, tunnel_dns=True)
    protocols = [i.get("protocol") for i in runtime.get("inbounds") or []]
    assert protocols == ["tun"]
    assert runtime["inbounds"][0]["settings"]["name"] == "incy-xray"


def test_resolve_config_from_incy_db_full_config(tmp_path, monkeypatch):
    import json

    from incy.config import resolve_config

    db = tmp_path / "incy.db"
    conn = sqlite3.connect(db)
    cfg = {
        "remarks": "🇩🇪 DE",
        "outbounds": [
            {
                "protocol": "vless",
                "tag": "proxy",
                "settings": {"vnext": [{"address": "1.2.3.4", "port": 443}]},
            }
        ],
    }
    conn.executescript(
        """
        CREATE TABLE subscriptions (id TEXT PRIMARY KEY, name TEXT, isEnabled INTEGER DEFAULT 1);
        CREATE TABLE servers (
            id TEXT PRIMARY KEY, name TEXT, subscriptionId TEXT, orderIndex INTEGER DEFAULT 0,
            fullConfigJson TEXT
        );
        INSERT INTO subscriptions VALUES ('sub1', 'Prov', 1);
        """
    )
    conn.execute(
        "INSERT INTO servers VALUES ('s1', ?, 'sub1', 0, ?)",
        ("🇩🇪 DE", json.dumps(cfg)),
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(incy_mod, "INCY_DB", db)

    runtime = resolve_config("🇩🇪 DE", provider_id="sub1", allow_fetch=False)
    assert runtime is not None
    assert any(i.get("protocol") == "tun" for i in runtime.get("inbounds") or [])


def test_incy_paths_from_desktop_exec(tmp_path, monkeypatch):
    from incy import paths as incy_paths

    root = tmp_path / "opt" / "incy"
    (root / "bin").mkdir(parents=True)
    (root / "lib" / "app" / "resources" / "bin").mkdir(parents=True)
    (root / "bin" / "incy").write_text("#!/bin/sh\n")
    library = root / "lib/app/resources/bin/libincycore.so"
    library.write_bytes(b"\x7fELF")
    library.with_name("libxray_ffi.so").write_bytes(b"\x7fELF")
    desktop = tmp_path / "incy.desktop"
    desktop.write_text(f"Exec={root / 'bin' / 'incy'} %u\n")
    monkeypatch.setattr(incy_paths, "DESKTOP", desktop)
    monkeypatch.setattr(incy_paths, "DEFAULT_ROOT", tmp_path / "missing")
    incy_paths.install_root.cache_clear()
    assert incy_paths.incy_installed()
    assert incy_paths.incy_library() == library
    library.with_name("libxray_ffi.so").unlink()
    assert not incy_paths.incy_installed()


def _patch_sub_cache(monkeypatch, tmp_path) -> Path:
    from incy import subscriptions as incy_subs

    cache = tmp_path / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("happ.constants.SUB_CACHE_DIR", cache)
    # Bound at import from the real ~/.cache; keep refresh state in tmp too.
    monkeypatch.setattr(incy_subs, "INCY_REFRESH", cache / "incy-subs-refresh.json")
    return cache


def _incy_db_with_sub(
    tmp_path, *, url="https://sub.example/v", sub_id="sub1"
) -> sqlite3.Connection:
    db = tmp_path / "incy.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE subscriptions (
            id TEXT PRIMARY KEY, name TEXT, customName TEXT, profileName TEXT,
            isEnabled INTEGER DEFAULT 1, orderIndex INTEGER DEFAULT 0, url TEXT
        );
        CREATE TABLE servers (
            id TEXT PRIMARY KEY, name TEXT, subscriptionId TEXT, orderIndex INTEGER DEFAULT 0,
            fullConfigJson TEXT
        );
        """
    )
    conn.execute(
        "INSERT INTO subscriptions VALUES (?, 'Raw', '', 'WireCat', 1, 0, ?)",
        (sub_id, url),
    )
    conn.commit()
    return conn


def test_subscription_url_and_name(tmp_path, monkeypatch):
    from incy import subscriptions as incy_subs

    _incy_db_with_sub(tmp_path)
    db_path = tmp_path / "incy.db"
    monkeypatch.setattr(incy_mod, "INCY_DB", db_path)
    assert incy_subs.subscription_url("sub1") == "https://sub.example/v"
    assert incy_subs.subscription_name("sub1") == "WireCat"
    assert incy_subs.subscription_url("missing") is None


def test_update_subscriptions_skips_fresh_cache(tmp_path, monkeypatch):
    from incy import subscriptions as incy_subs

    _incy_db_with_sub(tmp_path)
    monkeypatch.setattr(incy_mod, "INCY_DB", tmp_path / "incy.db")
    _patch_sub_cache(monkeypatch, tmp_path)
    incy_subs.SUB_CACHE_DIR.mkdir(parents=True)
    fresh = incy_subs.cache_path("sub1")
    fresh.write_text(
        json.dumps(
            {
                "at": time.time(),
                "url": "https://sub.example/v",
                "servers": [{"remarks": "S"}],
            }
        )
    )
    fetched = []
    monkeypatch.setattr(
        incy_subs,
        "fetch_servers",
        lambda sid, force=False: fetched.append((sid, force)) or ([], None),
    )
    assert incy_subs.update_subscriptions(force=False) == {}
    assert fetched == []


def test_update_subscriptions_force_refreshes(tmp_path, monkeypatch):
    from incy import subscriptions as incy_subs

    _incy_db_with_sub(tmp_path)
    monkeypatch.setattr(incy_mod, "INCY_DB", tmp_path / "incy.db")
    _patch_sub_cache(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(
        incy_subs,
        "fetch_servers",
        lambda sid, force=False: calls.append((sid, force)) or ([{"remarks": "🇩🇪 DE"}], None),
    )
    assert incy_subs.update_subscriptions(force=True) == {}
    assert calls == [("sub1", True)]


def test_update_subscriptions_records_fetch_errors(tmp_path, monkeypatch):
    from incy import subscriptions as incy_subs

    _incy_db_with_sub(tmp_path)
    monkeypatch.setattr(incy_mod, "INCY_DB", tmp_path / "incy.db")
    _patch_sub_cache(monkeypatch, tmp_path)
    monkeypatch.setattr(
        incy_subs,
        "fetch_servers",
        lambda sid, force=False: ([], "timeout"),
    )
    assert incy_subs.update_subscriptions(force=True) == {"WireCat": "timeout"}


def test_fetch_servers_without_url_returns_error(tmp_path, monkeypatch):
    from incy import subscriptions as incy_subs

    db = tmp_path / "incy.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE subscriptions (
            id TEXT PRIMARY KEY, name TEXT, isEnabled INTEGER DEFAULT 1, url TEXT
        );
        INSERT INTO subscriptions VALUES ('sub1', 'P', 1, NULL);
        """
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(incy_mod, "INCY_DB", db)
    servers, err = incy_subs.fetch_servers("sub1")
    assert servers == []
    assert err == "subscription not in incy.db"


def test_subscription_targets_from_db(tmp_path, monkeypatch):
    from incy import subscriptions as incy_subs

    _incy_db_with_sub(tmp_path, url="https://panel.example:8443/sub")
    monkeypatch.setattr(incy_mod, "INCY_DB", tmp_path / "incy.db")
    targets = incy_subs.subscription_targets()
    assert targets == [("WireCat", "panel.example", 8443)]


def test_all_catalog_entries_merges_db_and_cache(tmp_path, monkeypatch):
    from incy import subscriptions as incy_subs

    conn = _incy_db_with_sub(tmp_path)
    cfg = {"remarks": "🇩🇪 DE", "outbounds": [{"protocol": "vless", "tag": "proxy"}]}
    conn.execute(
        "INSERT INTO servers VALUES ('s1', '🇩🇪 DE', 'sub1', 0, ?)",
        (json.dumps(cfg),),
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(incy_mod, "INCY_DB", tmp_path / "incy.db")
    _patch_sub_cache(monkeypatch, tmp_path)
    entries = incy_subs.all_catalog_entries(allow_fetch=False)
    assert any(e["name"] == "🇩🇪 DE" and e["provider_id"] == "sub1" for e in entries)


def test_incy_provider_ping_targets(tmp_path, monkeypatch):
    conn = _incy_db_with_sub(tmp_path)
    cfg = {
        "remarks": "🇩🇪 DE",
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {"vnext": [{"address": "203.0.113.1", "port": 443}]},
            }
        ],
    }
    conn.execute(
        "INSERT INTO servers VALUES ('s1', '🇩🇪 DE', 'sub1', 0, ?)",
        (json.dumps(cfg),),
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(incy_mod, "INCY_DB", tmp_path / "incy.db")
    targets = IncyProvider().ping_targets()
    assert ("🇩🇪 DE", "203.0.113.1", 443) in targets


def test_incy_connect_refuses_when_app_owns_tunnel(monkeypatch):
    monkeypatch.setattr(incy_mod, "incy_installed", lambda: True)
    monkeypatch.setattr("providers.happd.incy.app_connected", lambda: True)
    r = IncyProvider().connect(
        VPNConnection("S", "INCY", False, subscription_id="sub1"),
    )
    assert not r.success
    assert "INCY app" in r.message


def test_incy_connect_starts_keeper(monkeypatch, tmp_path):
    monkeypatch.setattr(incy_mod, "incy_installed", lambda: True)
    monkeypatch.setattr("providers.happd.incy.app_connected", lambda: False)
    monkeypatch.setattr(incy_mod, "KEEPER_STATE", tmp_path / "keeper.json")
    popen_cmds = []
    monkeypatch.setattr(
        incy_mod.subprocess,
        "Popen",
        lambda cmd, **kw: popen_cmds.append(cmd) or SimpleNamespace(pid=42),
    )
    provider = IncyProvider()
    monkeypatch.setattr(
        provider,
        "_await_keeper",
        lambda _deadline, pid: ActionResult(True, "Connected: 🇩🇪 DE"),
    )
    r = provider.connect(
        VPNConnection("🇩🇪 DE", "INCY", False, subscription_id="sub1"),
    )
    assert r.success
    assert popen_cmds and "--incy-keeper" in popen_cmds[0]
    assert "sub1" in popen_cmds[0]


def test_incy_disconnect_when_not_up(tmp_path, monkeypatch):
    monkeypatch.setattr(incy_mod, "KEEPER_STATE", tmp_path / "keeper.json")
    r = IncyProvider().disconnect(VPNConnection("S", "INCY", True))
    assert not r.success


def test_incy_disconnect_clears_tunnel(monkeypatch, tmp_path):
    import providers.happd.incy as incy_impl
    from incy.config import TUN_IFACE

    monkeypatch.setattr(incy_mod, "KEEPER_STATE", tmp_path / "keeper.json")
    (tmp_path / "keeper.json").write_text('{"status":"connected"}')
    tun = f"/sys/class/net/{TUN_IFACE}"
    checks = {"n": 0}
    real_exists = Path.exists

    def exists(self):
        if str(self) == tun:
            checks["n"] += 1
            return checks["n"] == 1
        return real_exists(self)

    monkeypatch.setattr(Path, "exists", exists)
    monkeypatch.setattr(incy_impl, "time", SimpleNamespace(time=lambda: 0, sleep=lambda _: None))
    r = IncyProvider().disconnect(VPNConnection("S", "INCY", True))
    assert r.success


def test_run_keeper_connects_with_mock_xray(tmp_path, monkeypatch):
    from incy import keeper
    from incy.config import TUN_IFACE

    monkeypatch.setattr(incy_mod, "KEEPER_STATE", tmp_path / "keeper.json")
    cfg = {
        "remarks": "🇩🇪 DE",
        "inbounds": [{"protocol": "tun", "settings": {"name": TUN_IFACE}}],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }
    monkeypatch.setattr(keeper, "resolve_config", lambda *a, **k: cfg)
    monkeypatch.setattr(keeper, "config_error", lambda _c: None)
    proc = SimpleNamespace(
        pid=99,
        poll=lambda: 0,
        terminate=lambda: None,
        wait=lambda timeout=0: 0,
    )
    monkeypatch.setattr(keeper, "popen_xray", lambda *a, **k: proc)
    monkeypatch.setattr(keeper, "_wait_iface", lambda _d: True)
    keeper.run_keeper("🇩🇪 DE", "sub1")
    state = json.loads((tmp_path / "keeper.json").read_text())
    assert state.get("status") == "exited"
    assert state.get("server") == "🇩🇪 DE"


def test_update_incy_subs_cli_logs_failures(monkeypatch):
    import incy.subscriptions as incy_subs

    monkeypatch.setattr(vpn_manager.sys, "argv", ["vpn_manager.py", "--update-incy-subs"])
    logged = []
    monkeypatch.setattr(vpn_manager.logutil, "log", logged.append)
    monkeypatch.setattr(incy_subs, "update_subscriptions", lambda force=False: {"P": "HTTP 403"})
    vpn_manager.main()
    assert any("HTTP 403" in line for line in logged)


def test_manual_incy_subscription_refresh_refreshes_bar(monkeypatch):
    import incy.subscriptions as incy_subs

    monkeypatch.setattr(vpn_manager.sys, "argv", ["vpn_manager.py", "--update-incy-subs-force"])
    refreshed = []
    monkeypatch.setattr(
        incy_subs,
        "update_subscriptions",
        lambda force=False: {"Bad": "timeout"} if force else {},
    )
    monkeypatch.setattr(vpn_manager, "refresh_bar", lambda: refreshed.append(True))
    vpn_manager.main()
    assert refreshed == [True]


def test_killswitch_targets_for_incy(monkeypatch):
    class Incy:
        name = "INCY"

    conn = VPNConnection("🇩🇪 DE", "INCY", False, subscription_id="sub1")
    monkeypatch.setattr(
        vpn_manager,
        "killswitch",
        vpn_manager.killswitch,
    )
    monkeypatch.setattr(
        "incy.config.server_endpoints",
        lambda name, provider_id=None, allow_fetch=False: [("203.0.113.5", 443)],
    )
    monkeypatch.setattr(
        "incy.subscriptions.subscription_targets",
        lambda: [("WireCat", "sub.example", 443)],
    )
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "resolve_endpoint_ips",
        lambda targets, cached_only=False: ["203.0.113.5", "198.51.100.1"],
    )
    ips, ifaces = vpn_manager._killswitch_targets(Incy(), conn)
    assert ips == ["203.0.113.5", "198.51.100.1"]
    assert ifaces == ["incy-xray"]


def test_panel_connect_incy_needs_matching_subscription(monkeypatch):
    conn = VPNConnection(
        "🇩🇪 DE",
        "INCY",
        False,
        subscription_id="sub1",
        subscription_name="WireCat",
    )

    class Incy:
        name = "INCY"

        def connections(self):
            return [conn]

    calls = []

    monkeypatch.setattr(
        vpn_manager,
        "guarded_connect",
        lambda provider, connection: (
            calls.append((provider.name, connection.subscription_id)) or ActionResult(True, "up")
        ),
    )
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [Incy()])
    assert vpn_manager.panel_connect("INCY", "🇩🇪 DE", "sub1").success
    assert calls == [("INCY", "sub1")]
    assert not vpn_manager.panel_connect("INCY", "🇩🇪 DE", "wrong-sub").success
