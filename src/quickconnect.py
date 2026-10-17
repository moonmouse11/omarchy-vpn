"""Quick connect: favourite servers and the last few connected (the app
window's and the panel's QUICK CONNECT chips; the power switch reconnects
the last one).

~/.config/vpn-manager/quick.json — config, not cache: 🗑 Clear Caches must
not wipe favourites. A server is (provider, name, sub_id) — Happ's identity
is its subscription plus name (two subscriptions both ship "🇩🇪 Germany");
sub_id is "" for every other provider.
"""

import contextlib
import json
from pathlib import Path

import fsutil

QUICK_FILE = Path.home() / ".config" / "vpn-manager" / "quick.json"
RECENT_MAX = 3  # the user's pick


def _entry(provider: str, name: str, sub_id: str | None) -> dict:
    return {"provider": provider, "name": name, "sub_id": sub_id or ""}


def load() -> dict:
    """{favourites: [...], recent: [...]} — newest recent first; empty on any
    unreadable file (a broken quick.json must not break the server list)."""
    try:
        raw = json.loads(QUICK_FILE.read_text())
    except OSError, ValueError:
        raw = {}
    if not isinstance(raw, dict):
        raw = {}

    def entries(key: str) -> list[dict]:
        items = raw.get(key)
        if not isinstance(items, list):
            return []
        return [
            _entry(str(e["provider"]), str(e["name"]), str(e.get("sub_id") or ""))
            for e in items
            if isinstance(e, dict) and e.get("provider") and e.get("name")
        ]

    return {"favourites": entries("favourites"), "recent": entries("recent")[:RECENT_MAX]}


def _save(data: dict) -> None:
    with contextlib.suppress(OSError):
        fsutil.write_json_atomic(QUICK_FILE, data, indent=2)


def remember(provider: str, name: str, sub_id: str | None = None) -> None:
    """A successful connect: first in recent, no duplicates, RECENT_MAX kept."""
    data = load()
    entry = _entry(provider, name, sub_id)
    data["recent"] = [entry, *(e for e in data["recent"] if e != entry)][:RECENT_MAX]
    _save(data)


def toggle_favourite(provider: str, name: str, sub_id: str | None = None) -> bool:
    """Star / unstar a server; True when it is a favourite now."""
    data = load()
    entry = _entry(provider, name, sub_id)
    starred = entry not in data["favourites"]
    data["favourites"] = (
        [*data["favourites"], entry] if starred else [e for e in data["favourites"] if e != entry]
    )
    _save(data)
    return starred
