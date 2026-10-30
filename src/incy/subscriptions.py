"""INCY subscriptions: URLs from incy.db, caches under ~/.cache/vpn-manager/."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from happ.constants import SUB_CACHE_DIR, SUB_MAX_AGE
from incy.headers import incy_headers
from subscription.fetch import fetch_subscription_to_cache

INCY_DB = Path.home() / ".local/share/incy/incy.db"


def _safe_id(sub_id: str) -> str:
    return re.sub(r"[^\w-]", "_", sub_id)


def cache_path(sub_id: str) -> Path:
    return SUB_CACHE_DIR / f"incy-subscription-{_safe_id(sub_id)}.json"


def subscription_url(sub_id: str) -> str | None:
    if not INCY_DB.is_file():
        return None
    try:
        conn = sqlite3.connect(f"file:{INCY_DB}?mode=ro", uri=True, timeout=1.0)
        row = conn.execute(
            "SELECT url FROM subscriptions WHERE id = ? AND isEnabled = 1",
            (sub_id,),
        ).fetchone()
        conn.close()
    except sqlite3.Error:
        return None
    return row[0] if row else None


def subscription_name(sub_id: str) -> str:
    if not INCY_DB.is_file():
        return "INCY"
    try:
        conn = sqlite3.connect(f"file:{INCY_DB}?mode=ro", uri=True, timeout=1.0)
        row = conn.execute(
            "SELECT COALESCE(NULLIF(customName, ''), name) FROM subscriptions WHERE id = ?",
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


def _servers_from_cache(sub_id: str) -> list[dict]:
    path = cache_path(sub_id)
    try:
        cached = json.loads(path.read_text())
    except OSError, json.JSONDecodeError:
        return []
    if not isinstance(cached, dict):
        return []
    return list(cached.get("servers") or [])


def all_catalog_entries(*, allow_fetch: bool = True) -> list[dict]:
    if not INCY_DB.is_file():
        return []
    try:
        conn = sqlite3.connect(f"file:{INCY_DB}?mode=ro", uri=True, timeout=1.0)
        sub_ids = [
            r[0]
            for r in conn.execute(
                "SELECT id FROM subscriptions WHERE isEnabled = 1 ORDER BY orderIndex"
            ).fetchall()
        ]
        conn.close()
    except sqlite3.Error:
        return []
    out: list[dict] = []
    for sub_id in sub_ids:
        if allow_fetch:
            servers, _err = fetch_servers(sub_id, force=False)
            if not servers:
                servers, _err = fetch_servers(sub_id, force=True)
        else:
            servers = _servers_from_cache(sub_id)
        for cfg in servers:
            if str(cfg.get("remarks") or ""):
                out.append(catalog_entry(sub_id, cfg))
    return out
