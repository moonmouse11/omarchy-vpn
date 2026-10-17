"""Quick connect: favourite servers and the last few connected (the app
window's and the panel's QUICK CONNECT chips; the power switch reconnects
the last one).

~/.config/vpn-manager/quick.json — config, not cache: 🗑 Clear Caches must
not wipe favourites. A server is (provider, name, sub_id) — Happ's identity
is its subscription plus name (two subscriptions both ship "🇩🇪 Germany");
sub_id is "" for every other provider.
"""

import contextlib
import fcntl
import json
from collections.abc import Iterator
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


# a connect's remember() and a star's toggle run in separate processes: one
# read-modify-write at a time, or the later save drops the other's change
@contextlib.contextmanager
def _locked() -> Iterator[dict]:
    """load() under an flock, saved on exit (OSError propagates)."""
    QUICK_FILE.parent.mkdir(parents=True, exist_ok=True)
    with QUICK_FILE.with_suffix(".lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        data = load()
        yield data
        fsutil.write_json_atomic(QUICK_FILE, data, indent=2)


def remember(provider: str, name: str, sub_id: str | None = None) -> None:
    """A successful connect: first in recent, no duplicates, RECENT_MAX kept.
    Best effort — a full disk must not turn a working connect into an error."""
    entry = _entry(provider, name, sub_id)
    with contextlib.suppress(OSError), _locked() as data:
        data["recent"] = [entry, *(e for e in data["recent"] if e != entry)][:RECENT_MAX]


def toggle_favourite(provider: str, name: str, sub_id: str | None = None) -> bool:
    """Star / unstar a server; True when it is a favourite now. Raises
    OSError when it couldn't be saved (the caller says so)."""
    entry = _entry(provider, name, sub_id)
    with _locked() as data:
        starred = entry not in data["favourites"]
        data["favourites"] = (
            [*data["favourites"], entry]
            if starred
            else [e for e in data["favourites"] if e != entry]
        )
    return starred
