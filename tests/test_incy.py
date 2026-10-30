"""INCY provider: read-only incy.db listing."""

import sqlite3

import providers.incy as incy_mod
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
    assert conns[0].active is True

    _all, groups = incy_server_groups(provider)
    assert "WireCat VPN" in groups
    assert groups["WireCat VPN"][0]["provider_id"] == "sub1"


def test_connect_refuses_when_incy_not_installed(monkeypatch):
    monkeypatch.setattr(incy_mod, "incy_installed", lambda: False)
    from providers.common.types import VPNConnection

    r = IncyProvider().connect(VPNConnection("x", "INCY", False))
    assert not r.success
    assert "not found" in r.message.lower() or "not installed" in r.message.lower()


def test_fetch_incy_subscription_cache(tmp_path, monkeypatch):
    from incy import subscriptions as incy_subs

    monkeypatch.setattr(incy_subs, "SUB_CACHE_DIR", tmp_path)
    monkeypatch.setattr(
        incy_subs,
        "fetch_subscription_to_cache",
        lambda path, url, headers, **kw: ([{"remarks": "S1", "outbounds": [{}]}], None),
    )
    monkeypatch.setattr(incy_subs, "subscription_url", lambda _sid: "https://example/sub")
    servers, err = incy_subs.fetch_servers("sub1")
    assert err is None
    assert servers[0]["remarks"] == "S1"


def test_incy_paths_from_desktop_exec(tmp_path, monkeypatch):
    from incy import paths as incy_paths

    root = tmp_path / "opt" / "incy"
    (root / "bin").mkdir(parents=True)
    (root / "lib" / "app" / "resources" / "bin").mkdir(parents=True)
    (root / "bin" / "incy").write_text("#!/bin/sh\n")
    xray = root / "lib" / "app" / "resources" / "bin" / "xray"
    xray.write_bytes(b"\x7fELF")
    desktop = tmp_path / "incy.desktop"
    desktop.write_text(f"Exec={root / 'bin' / 'incy'} %u\n")
    monkeypatch.setattr(incy_paths, "DESKTOP", desktop)
    monkeypatch.setattr(incy_paths, "DEFAULT_ROOT", tmp_path / "missing")
    incy_paths.install_root.cache_clear()
    assert incy_paths.incy_installed()
    assert incy_paths.incy_xray() == xray
