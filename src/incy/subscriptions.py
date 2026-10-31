"""INCY subscriptions: URLs from incy.db, caches under ~/.cache/vpn-manager/."""

from __future__ import annotations

import contextlib
import json
import re
import sqlite3
import time
import urllib.parse
from pathlib import Path

from app.spawn import spawn_manager
from happ.constants import SUB_CACHE_DIR, SUB_MAX_AGE
from incy.headers import incy_headers
from subscription.fetch import fetch_subscription_to_cache

INCY_DB = Path.home() / ".local/share/incy/incy.db"
INCY_REFRESH = SUB_CACHE_DIR / "incy-subs-refresh.json"
INCY_REFRESH_RETRY = 300.0  # s — same idea as Happ's subs-refresh gate


def _incy_db() -> Path:
    import providers.incy as m  # noqa: PLC0415 — tests patch providers.incy.INCY_DB

    return m.INCY_DB


def _safe_id(sub_id: str) -> str:
    return re.sub(r"[^\w-]", "_", sub_id)


def cache_path(sub_id: str) -> Path:
    return SUB_CACHE_DIR / f"incy-subscription-{_safe_id(sub_id)}.json"


def subscription_url(sub_id: str) -> str | None:
    db = _incy_db()
    if not db.is_file():
        return None
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.0)
        row = conn.execute(
            "SELECT url FROM subscriptions WHERE id = ? AND isEnabled = 1",
            (sub_id,),
        ).fetchone()
        conn.close()
    except sqlite3.Error:
        return None
    return row[0] if row else None


def subscription_name(sub_id: str) -> str:
    db = _incy_db()
    if not db.is_file():
        return "INCY"
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.0)
        row = conn.execute(
            """
            SELECT COALESCE(NULLIF(profileName, ''), NULLIF(customName, ''), name)
            FROM subscriptions WHERE id = ?
            """,
            (sub_id,),
        ).fetchone()
        conn.close()
    except sqlite3.Error:
        return "INCY"
    return row[0] if row else "INCY"


def fetch_servers(sub_id: str, *, force: bool = False) -> tuple[list[dict], str | None]:
    url = subscription_url(sub_id)
    if not url:
        return [], "subscription not in incy.db"
    return fetch_subscription_to_cache(
        cache_path(sub_id),
        url,
        incy_headers(),
        force=force,
        max_age=SUB_MAX_AGE,
    )


def catalog_entry(sub_id: str, cfg: dict) -> dict:
    name = str(cfg.get("remarks") or "")
    return {
        "name": name,
        "config": cfg,
        "provider_id": sub_id,
        "provider_name": subscription_name(sub_id),
    }


def db_server_raw_config(name: str, subscription_id: str | None = None) -> dict | None:
    """Per-server xray JSON persisted by the INCY app (works offline)."""
    db = _incy_db()
    if not db.is_file() or not name:
        return None
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.0)
        if subscription_id:
            row = conn.execute(
                """
                SELECT fullConfigJson FROM servers
                WHERE name = ? AND subscriptionId = ?
                  AND fullConfigJson IS NOT NULL AND fullConfigJson != ''
                """,
                (name, subscription_id),
            ).fetchone()
        else:
            row = conn.execute(
                """
                SELECT fullConfigJson FROM servers
                WHERE name = ? AND fullConfigJson IS NOT NULL AND fullConfigJson != ''
                ORDER BY orderIndex LIMIT 1
                """,
                (name,),
            ).fetchone()
        conn.close()
    except sqlite3.Error:
        return None
    if not row or not row[0]:
        return None
    try:
        cfg = json.loads(row[0])
    except json.JSONDecodeError:
        return None
    return cfg if isinstance(cfg, dict) else None


def all_db_catalog_entries() -> list[dict]:
    db = _incy_db()
    if not db.is_file():
        return []
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.0)
        rows = conn.execute(
            """
            SELECT s.name, s.subscriptionId, s.fullConfigJson
            FROM servers s
            JOIN subscriptions sub ON sub.id = s.subscriptionId
            WHERE (sub.isEnabled IS NULL OR sub.isEnabled = 1)
              AND s.fullConfigJson IS NOT NULL AND s.fullConfigJson != ''
            ORDER BY COALESCE(sub.orderIndex, 0), s.orderIndex, s.name
            """
        ).fetchall()
        conn.close()
    except sqlite3.Error:
        return []
    out: list[dict] = []
    for sname, sub_id, raw in rows:
        if not sname or not sub_id:
            continue
        try:
            cfg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(cfg, dict):
            continue
        if not str(cfg.get("remarks") or sname):
            cfg = {**cfg, "remarks": sname}
        out.append(catalog_entry(sub_id, cfg))
    return out


def _servers_from_cache(sub_id: str) -> list[dict]:
    path = cache_path(sub_id)
    try:
        cached = json.loads(path.read_text())
    except OSError, json.JSONDecodeError:
        return []
    if not isinstance(cached, dict):
        return []
    return list(cached.get("servers") or [])


def _sub_cache_fresh(sub_id: str) -> bool:
    path = cache_path(sub_id)
    try:
        cached = json.loads(path.read_text())
        return (
            isinstance(cached, dict)
            and cached.get("url") == subscription_url(sub_id)
            and time.time() - cached.get("at", 0) < SUB_MAX_AGE
        )
    except OSError, json.JSONDecodeError, TypeError:
        return False


def _incy_refresh_in_progress() -> bool:
    try:
        state = json.loads(INCY_REFRESH.read_text())
        return time.time() - state.get("at", 0) < INCY_REFRESH_RETRY
    except OSError, json.JSONDecodeError, TypeError:
        return False


def request_subscription_update() -> None:
    """Background refresh of INCY subscription caches when stale (connect uses incy.db)."""
    if _incy_refresh_in_progress():
        return
    db = _incy_db()
    if not db.is_file():
        return
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.0)
        sub_ids = [r[0] for r in conn.execute("SELECT id FROM subscriptions WHERE isEnabled = 1")]
        conn.close()
    except sqlite3.Error:
        return
    for sub_id in sub_ids:
        if subscription_url(sub_id) and not _sub_cache_fresh(sub_id):
            with contextlib.suppress(OSError):
                spawn_manager("--update-incy-subs")
            return


def update_subscriptions(force: bool = False) -> dict[str, str]:
    """Refresh every INCY subscription cache (--update-incy-subs)."""
    INCY_REFRESH.parent.mkdir(parents=True, exist_ok=True)
    INCY_REFRESH.write_text(json.dumps({"at": time.time()}))
    failed: dict[str, str] = {}
    db = _incy_db()
    if not db.is_file():
        return failed
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.0)
        rows = conn.execute(
            """
            SELECT id, COALESCE(NULLIF(profileName, ''), NULLIF(customName, ''), name)
            FROM subscriptions WHERE isEnabled = 1
            """
        ).fetchall()
        conn.close()
    except sqlite3.Error:
        return failed
    for sub_id, title in rows:
        if not subscription_url(sub_id):
            continue
        if not force and _sub_cache_fresh(sub_id):
            continue
        _servers, err = fetch_servers(sub_id, force=force or not _sub_cache_fresh(sub_id))
        if err:
            failed[title or sub_id] = err
    with contextlib.suppress(OSError):
        INCY_REFRESH.write_text(json.dumps({"at": time.time(), "failed": failed}))
    return failed


def subscription_targets() -> list[tuple[str, str, int]]:
    """Subscription panel hosts — refreshes go direct and need killswitch holes."""
    targets: list[tuple[str, str, int]] = []
    db = _incy_db()
    if not db.is_file():
        return targets
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.0)
        rows = conn.execute(
            """
            SELECT COALESCE(NULLIF(profileName, ''), NULLIF(customName, ''), name), url
            FROM subscriptions WHERE isEnabled = 1
            """
        ).fetchall()
        conn.close()
    except sqlite3.Error:
        return targets
    for title, url in rows:
        parsed = urllib.parse.urlsplit(url or "")
        if parsed.hostname:
            targets.append((title or "INCY", parsed.hostname, parsed.port or 443))
    return targets


def all_catalog_entries(*, allow_fetch: bool = True) -> list[dict]:
    by_key: dict[tuple[str, str], dict] = {}
    for entry in all_db_catalog_entries():
        by_key[(entry["provider_id"], entry["name"])] = entry

    db = _incy_db()
    if not db.is_file():
        return list(by_key.values())
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.0)
        sub_ids = [
            r[0]
            for r in conn.execute(
                "SELECT id FROM subscriptions WHERE isEnabled = 1 ORDER BY orderIndex"
            ).fetchall()
        ]
        conn.close()
    except sqlite3.Error:
        return list(by_key.values())

    for sub_id in sub_ids:
        if allow_fetch:
            servers, _err = fetch_servers(sub_id, force=False)
            if not servers:
                servers, _err = fetch_servers(sub_id, force=True)
        else:
            servers = _servers_from_cache(sub_id)
        for cfg in servers:
            name = str(cfg.get("remarks") or "")
            if name:
                by_key.setdefault((sub_id, name), catalog_entry(sub_id, cfg))
    return list(by_key.values())
