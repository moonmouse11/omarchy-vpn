import json
import time

from lazyimports import statistics


def _happmeta():
    import happmeta as hm  # noqa: PLC0415 — tests patch happmeta.PING_CACHE

    return hm


def ping_key(name: str, subscription_id: str | None = None) -> str:
    """The ping cache key: Happ server names are unique only within one
    subscription (two often both ship a "🇩🇪 Germany"), so a subscription
    server is keyed by (subscription id, name); everything else by name."""
    return f"{subscription_id}\t{name}" if subscription_id else name


def read_pings() -> dict:
    hm = _happmeta()
    reader = getattr(hm, "_read_pings", None)
    if reader is not None and reader is not read_pings:
        data = reader()
        return data if isinstance(data, dict) else {}
    try:
        data = json.loads(hm.PING_CACHE.read_text())
    except OSError, json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def ping_ms(name: str) -> float | None:
    entry = read_pings().get(name)
    if not entry:
        return None
    if time.time() - entry.get("at", 0) > _happmeta().PING_MAX_AGE:
        return None
    return entry.get("ms")


def provider_ping_summary(names: list[str]) -> str | None:
    """'✓ reachable/total · ⌀median ms' for a provider's servers — cache only."""
    pings = read_pings()
    now = time.time()
    max_age = _happmeta().PING_MAX_AGE
    fresh_ms = []
    for name in names:
        entry = pings.get(name)
        if not isinstance(entry, dict) or now - entry.get("at", 0) > max_age:
            continue
        if entry.get("ms") is not None:
            fresh_ms.append(entry["ms"])
    if not fresh_ms:
        return None
    return f"✓ {len(fresh_ms)}/{len(names)} · ⌀{round(statistics.median(fresh_ms))}ms"


def _fresh_ping_entry(name: str) -> dict | None:
    entry = read_pings().get(name)
    if not isinstance(entry, dict) or time.time() - entry.get("at", 0) > _happmeta().PING_MAX_AGE:
        return None
    return entry


def ping_at(name: str) -> float:
    entry = read_pings().get(name)
    at = entry.get("at") if isinstance(entry, dict) else None
    return float(at) if isinstance(at, (int, float)) else 0.0


def ping_status(name: str) -> tuple[str, float | None]:
    entry = read_pings().get(name)
    if not isinstance(entry, dict) or "at" not in entry:
        return "none", None
    if entry.get("skipped"):
        return "skipped", None
    fresh = time.time() - entry.get("at", 0) <= _happmeta().PING_MAX_AGE
    return ("fresh" if fresh else "stale"), entry.get("ms")


def ping_mark(name: str) -> str:
    entry = _fresh_ping_entry(name)
    if entry is None or entry.get("skipped"):
        return ""
    if entry.get("ms") is None:
        return "⛔"
    return f"✓ {entry['ms']:.0f} ms"


def __getattr__(name: str):
    if name == "PING_CACHE":
        return _happmeta().PING_CACHE
    if name == "PING_MAX_AGE":
        return _happmeta().PING_MAX_AGE
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
