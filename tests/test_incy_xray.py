"""INCY xray staging, config validation, and keeper error paths."""

import json
import sqlite3
from types import SimpleNamespace

import pytest

import providers.incy as incy_mod
from incy import keeper, xray, xray_run
from incy.config import build_incy_runtime_config, resolve_config, server_endpoints
from providers.happd.incy import IncyProvider


def test_preflight_checks_library_without_starting_network(monkeypatch, tmp_path):
    library = tmp_path / "libincycore.so"
    monkeypatch.setattr(xray, "_incy_library", lambda: library)
    assert xray.config_error({}) == "INCY core library missing"
    library.touch()
    assert xray.config_error({"outbounds": []}) is None
    assert xray.config_error({"outbounds": "invalid"}) == "INCY outbounds must be a list"


def test_asset_dir_finds_geoip_under_install_root(monkeypatch, tmp_path):
    root = tmp_path / "incy"
    geo = root / "lib/app/resources"
    geo.mkdir(parents=True)
    (geo / "geoip.dat").write_bytes(b"geo")
    monkeypatch.setattr(xray, "GEO_DIRS", ())
    monkeypatch.setattr(xray, "install_root", lambda: root)
    assert xray.asset_dir() == geo


def test_popen_xray_rejects_bad_slot():
    with pytest.raises(ValueError, match="bad incy config slot"):
        xray_run.popen_xray({}, "evil.json")


def _keeper_state_recorder(monkeypatch, tmp_path):
    monkeypatch.setattr(incy_mod, "KEEPER_STATE", tmp_path / "keeper.json")
    recorded: list[dict] = []
    monkeypatch.setattr(keeper, "_write_state", lambda s: recorded.append(dict(s)))
    monkeypatch.setattr(keeper, "_write_own_state", lambda s: recorded.append(dict(s)))
    monkeypatch.setattr(keeper, "_read_state", lambda: None)
    return recorded


def test_keeper_retries_resolve_with_fetch(monkeypatch, tmp_path):
    _keeper_state_recorder(monkeypatch, tmp_path)
    calls = []

    def resolve(name, provider_id=None, allow_fetch=False):
        calls.append(allow_fetch)
        return {"remarks": "x"} if allow_fetch else None

    monkeypatch.setattr(keeper, "resolve_config", resolve)
    monkeypatch.setattr(keeper, "config_error", lambda _c: "bad")
    keeper.run_keeper("x", "sub1")
    assert calls == [False, True]


def test_keeper_reports_missing_config(monkeypatch, tmp_path):
    recorded = _keeper_state_recorder(monkeypatch, tmp_path)
    monkeypatch.setattr(keeper, "resolve_config", lambda *a, **k: None)
    keeper.run_keeper("missing", "sub1")
    errors = [s for s in recorded if s.get("status") == "error"]
    assert errors and "no config" in errors[-1]["message"]


def test_keeper_reports_config_error(monkeypatch, tmp_path):
    recorded = _keeper_state_recorder(monkeypatch, tmp_path)
    monkeypatch.setattr(keeper, "resolve_config", lambda *a, **k: {"remarks": "x"})
    monkeypatch.setattr(keeper, "config_error", lambda _c: "bad tag")
    keeper.run_keeper("x", "sub1")
    errors = [s for s in recorded if s.get("status") == "error"]
    assert errors and "xray rejected" in errors[-1]["message"]


def test_keeper_reports_tun_timeout(monkeypatch, tmp_path):
    recorded = _keeper_state_recorder(monkeypatch, tmp_path)
    monkeypatch.setattr(keeper, "resolve_config", lambda *a, **k: {"remarks": "x"})
    monkeypatch.setattr(keeper, "config_error", lambda _c: None)
    proc = SimpleNamespace(
        pid=3,
        poll=lambda: None,
        terminate=lambda: None,
        wait=lambda **kw: 0,
    )
    monkeypatch.setattr(keeper, "popen_xray", lambda *a, **k: proc)
    monkeypatch.setattr(keeper, "_wait_iface", lambda _d: False)
    keeper.run_keeper("x", "sub1")
    errors = [s for s in recorded if s.get("status") == "error"]
    assert errors and "TUN" in errors[-1]["message"]


def test_tun_inbound_fallback_without_default_tun(monkeypatch):
    monkeypatch.setattr("incy.config.DEFAULT_INBOUNDS", [{"protocol": "socks", "tag": "socks"}])
    cfg = build_incy_runtime_config(
        {"remarks": "x", "outbounds": [{"protocol": "freedom", "tag": "direct"}]},
        tunnel_dns=False,
    )
    assert cfg["inbounds"][0]["protocol"] == "tun"
    assert cfg["inbounds"][0]["settings"]["name"] == "incy-xray"


def test_resolve_config_fetches_when_catalog_missing_sub(monkeypatch, tmp_path):
    from incy import subscriptions as incy_subs

    db = tmp_path / "incy.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE subscriptions (
            id TEXT PRIMARY KEY, name TEXT, isEnabled INTEGER DEFAULT 1, url TEXT
        );
        CREATE TABLE servers (id TEXT PRIMARY KEY, name TEXT, subscriptionId TEXT);
        INSERT INTO subscriptions VALUES ('sub1', 'P', 1, 'https://example/sub');
        """
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(incy_mod, "INCY_DB", db)
    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setattr("happ.constants.SUB_CACHE_DIR", cache)
    monkeypatch.setattr(incy_subs, "INCY_REFRESH", cache / "incy-subs-refresh.json")
    remote = {
        "remarks": "🇵🇱 PL",
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {"vnext": [{"address": "203.0.113.9", "port": 443}]},
            }
        ],
    }
    import incy.config as incy_config

    monkeypatch.setattr(incy_config, "all_catalog_entries", lambda allow_fetch=True: [])
    monkeypatch.setattr(incy_config, "fetch_servers", lambda sid, force=False: ([remote], None))
    runtime = resolve_config("🇵🇱 PL", provider_id="sub1", allow_fetch=True)
    assert runtime is not None
    eps = server_endpoints("🇵🇱 PL", provider_id="sub1", allow_fetch=True)
    assert eps == [("203.0.113.9", 443)]


def test_request_subscription_update_spawns_background_job(monkeypatch, tmp_path):
    from incy import subscriptions as incy_subs

    db = tmp_path / "incy.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE subscriptions (
            id TEXT PRIMARY KEY, name TEXT, isEnabled INTEGER DEFAULT 1, url TEXT
        );
        INSERT INTO subscriptions VALUES ('sub1', 'P', 1, 'https://example/sub');
        """
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(incy_mod, "INCY_DB", db)
    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setattr("happ.constants.SUB_CACHE_DIR", cache)
    refresh = cache / "incy-subs-refresh.json"
    monkeypatch.setattr(incy_subs, "INCY_REFRESH", refresh)
    refresh.write_text(json.dumps({"at": 0}))
    spawns = []
    monkeypatch.setattr(incy_subs, "spawn_manager", spawns.append)
    incy_subs.request_subscription_update()
    assert spawns == ["--update-incy-subs"]


def test_db_server_raw_config_bad_json(tmp_path, monkeypatch):
    from incy import subscriptions as incy_subs

    db = tmp_path / "incy.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE subscriptions (id TEXT PRIMARY KEY, name TEXT, isEnabled INTEGER DEFAULT 1);
        CREATE TABLE servers (id TEXT PRIMARY KEY, name TEXT, subscriptionId TEXT,
            orderIndex INTEGER DEFAULT 0, fullConfigJson TEXT);
        INSERT INTO subscriptions VALUES ('sub1', 'P', 1);
        """
    )
    conn.execute(
        "INSERT INTO servers VALUES ('s1', 'bad', 'sub1', 0, ?)",
        ("not-json",),
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(incy_mod, "INCY_DB", db)
    assert incy_subs.db_server_raw_config("bad", "sub1") is None


def test_app_connected_when_gui_xray_without_keeper(monkeypatch):
    import providers.happd.incy as incy_impl

    monkeypatch.setattr(incy_impl, "_GUI_LINK", SimpleNamespace(is_dir=lambda: True))
    assert incy_impl.app_connected() is True


def _advancing_time(monkeypatch, step: float = 0.25):
    clock = {"t": 0.0}

    def tick():
        clock["t"] += step
        return clock["t"]

    monkeypatch.setattr(incy_mod, "time", SimpleNamespace(time=tick, sleep=lambda _: None))


def test_await_keeper_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr(incy_mod, "KEEPER_STATE", tmp_path / "keeper.json")
    _advancing_time(monkeypatch)
    result = IncyProvider()._await_keeper(0.5, 99)
    assert not result.success
    assert "timeout" in result.message.lower()


def test_await_keeper_error_state(monkeypatch, tmp_path):
    monkeypatch.setattr(incy_mod, "KEEPER_STATE", tmp_path / "keeper.json")
    (tmp_path / "keeper.json").write_text(
        json.dumps({"pid": 99, "status": "error", "message": "boom"})
    )
    _advancing_time(monkeypatch)
    result = IncyProvider()._await_keeper(10.0, 99)
    assert not result.success
    assert result.message == "boom"


def test_import_config_refuses(monkeypatch):
    r = IncyProvider().import_config("/tmp/x")
    assert not r.success
    assert "INCY app" in r.message
