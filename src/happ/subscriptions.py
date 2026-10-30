"""Happ subscription metadata (subscriptions, xray runtime config, server registry)."""

import base64
import contextlib
import functools
import hashlib
import ipaddress
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import fsutil
from lazyimports import statistics  # noqa: F401 — registers urllib.request & co. lazily

if TYPE_CHECKING:
    pass

from happ.constants import *  # noqa: F403


def _happmeta():
    import happmeta as hm  # noqa: PLC0415 — tests patch happmeta.subprocess / urllib

    return hm


# ── Providers ─────────────────────────────────────────────────────────────────


def _parse_providers() -> dict[str, dict]:
    """subscription id -> {"name": str, "url": str | None}."""
    hm = _happmeta()
    if hm._parse_providers is not _parse_providers:
        return hm._parse_providers()
    log_file = hm.LOG_FILE
    routing_file = hm.ROUTING_FILE
    id_url: dict[str, str] = {}
    id_pos: dict[str, int] = {}  # last 'starting update from' position per id
    added_urls: list[tuple[int, str]] = []  # (position, url), log order
    url_name: dict[str, str] = {}
    try:
        text = log_file.read_text(errors="replace")
    except OSError:
        text = ""
    for m in re.finditer(r"Subscription #(-?\d+) starting update from: (\S+)", text):
        id_url[m.group(1)] = m.group(2)
        id_pos[m.group(1)] = m.start()
    # Newly added subscriptions log no id line — only this. The numeric id is
    # not available unencrypted (subs.db is AES-GCM), so synthesize a stable
    # id from the url; a later real id line for the same url always wins.
    added_urls.extend(
        (m.start(), m.group(1)) for m in re.finditer(r"Subscription being added: (\S+)", text)
    )
    # Atomic group around the repeated "[...]" prefix: once it has consumed
    # N bracket groups it commits to that count instead of retrying N-1,
    # N-2, ... against the trailing ".+?" when "fetching subscription from"
    # isn't found — that retry was O(n^2)-ish backtracking on a log file
    # that only grows, so a big log could stall the 3 s --status tick.
    for m in re.finditer(r"\](?>(?: ?\[[^\]]+\])*) ?(.+?) fetching subscription from (\S+)", text):
        name = m.group(1).strip()
        if name:
            url_name[m.group(2)] = name

    def _resolve_name(url: str, fallback: str) -> str:
        name = url_name.get(url)
        if not name:
            host = re.sub(r"^https?://", "", url).split("/")[0]
            name = next((n for u, n in url_name.items() if host in u), None)
        return name or fallback

    host_ids: dict[str, list[str]] = {}
    for sub_id, url in id_url.items():
        host = re.sub(r"^https?://", "", url).split("/")[0]
        host_ids.setdefault(host, []).append(sub_id)

    def _path_prefix_len(a: str, b: str) -> int:
        """Shared prefix length of url paths (scheme+host stripped) —
        /cart/TOKEN1 vs /cart/TOKEN2 share more than /a vs /cart/... ."""
        ra = re.sub(r"^https?://[^/]+", "", a)
        rb = re.sub(r"^https?://[^/]+", "", b)
        n = 0
        for ca, cb in zip(ra, rb, strict=False):
            if ca != cb:
                break
            n += 1
        return n

    synth: dict[str, str] = {}  # host -> url (last wins)
    for pos, url in added_urls:
        if url in id_url.values():
            continue
        host = re.sub(r"^https?://", "", url).split("/")[0]
        ids = host_ids.get(host)
        if ids:
            # Re-added with a fresh token for a host Happ already updates
            # under real id(s). Happ's own newest log line is ground truth:
            # an added line older than the host's latest real update line is
            # stale and must not regress (or duplicate) the provider.
            newest_real = max(id_pos[i] for i in ids)
            if pos < newest_real:
                continue
            # Path-aware pick: the id whose current url shares the longest
            # path prefix with the added url — a sibling subscription on the
            # same host must not swallow another's rotated token.
            real_id = max(ids, key=lambda i: _path_prefix_len(id_url[i], url))
            id_url[real_id] = url
            continue
        synth[host] = url

    providers: dict[str, dict] = {}
    for sub_id, url in id_url.items():
        providers[sub_id] = {"name": _resolve_name(url, f"Subscription {sub_id}"), "url": url}
    for host, url in synth.items():
        sub_id = "h" + hashlib.sha1(url.encode(), usedforsecurity=False).hexdigest()[:10]
        providers[sub_id] = {"name": _resolve_name(url, host), "url": url}

    # Fallback names from routing.json (routing names per subscription)
    try:
        routing = json.loads(routing_file.read_text())
        for r in routing.get("routings", []):
            sub_id = str(r.get("subscriptionId", ""))
            if sub_id and sub_id not in providers and r.get("name"):
                providers[sub_id] = {"name": r["name"], "url": None}
    except OSError, json.JSONDecodeError:
        pass
    return providers


PROVIDERS_CACHE_VERSION = 2  # bump when _parse_providers learns new log shapes


def providers() -> dict[str, dict]:
    """id -> {"name", "url"}, cached by the log's mtime."""
    hm = _happmeta()
    if hm.providers is not providers:
        return hm.providers()
    log_file = hm.LOG_FILE
    providers_cache = hm.PROVIDERS_CACHE
    try:
        mtime = log_file.stat().st_mtime
    except OSError:
        mtime = 0
    try:
        cache = json.loads(providers_cache.read_text())
        if cache.get("version") == PROVIDERS_CACHE_VERSION and cache.get("mtime") == mtime:
            return cache.get("providers", {})
    except OSError, json.JSONDecodeError:
        pass
    result = _parse_providers()
    # subscription URLs carry access tokens — fsutil writes 0600
    with contextlib.suppress(OSError):
        fsutil.write_json_atomic(
            providers_cache,
            {"version": PROVIDERS_CACHE_VERSION, "mtime": mtime, "providers": result},
        )
    return result


def captured_providers() -> dict[str, str]:
    """server name -> subscription id (sidecar written by the capture tool)."""
    try:
        data = json.loads(_happmeta().CAPTURED_PROVIDERS.read_text())
    except OSError, json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


# ── Subscription fetching ─────────────────────────────────────────────────────


def _captured_headers() -> dict[str, str] | None:
    """Request headers the user put in HEADERS_FILE (README: Happ setup)."""
    try:
        data = json.loads(_happmeta().HEADERS_FILE.read_text())
    except OSError, json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) and data else None


@functools.cache
def happ_version() -> str:
    """Installed Happ's version from the package owning its binary
    ("/usr/bin/happ is owned by happ-desktop-bin 1:4.5.2-1" -> "4.5.2"),
    whatever the AUR package is called. Only paid on a real fetch."""
    hm = _happmeta()
    subp = hm.subprocess
    try:
        out = subp.run(
            ["pacman", "-Qo", hm.HAPP_GUI_BIN],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,  # "not owned" exits 1; the regex below handles it
        ).stdout
    except OSError, subp.SubprocessError:
        out = ""
    m = re.search(r" is owned by \S+ (?:\d+:)?([0-9][\w.+]*)-[\w.]+$", out.strip())
    return m.group(1) if m else hm.HAPP_VERSION_FALLBACK


@functools.cache
def happ_hwid() -> str | None:
    """Happ's X-HWID: the machine id as QSysInfo::machineUniqueId() reads it."""
    for path in _happmeta().MACHINE_ID_FILES:
        with contextlib.suppress(OSError):
            if machine_id := path.read_text().strip():
                return machine_id
    return None


def default_headers() -> dict[str, str]:
    hm = _happmeta()
    headers = {"User-Agent": f"Happ/{hm.happ_version()}"}
    if hwid := hm.happ_hwid():
        headers["X-HWID"] = hwid
    return headers


def _headers() -> dict[str, str]:
    return _captured_headers() or default_headers()


def has_headers() -> bool:
    """Whether the request headers were captured — an empty server list
    without them may be a panel that rejects default_headers()."""
    return _captured_headers() is not None


# Outbounds that never reach a server, and addresses a panel's stub "server"
# points at (seen: 0.0.0.0 and 198.18.0.1).
_STUB_IGNORED_PROTOCOLS = (*NON_PROXY_PROTOCOLS, "loopback")
_PLACEHOLDER_NETS = tuple(ipaddress.ip_network(n) for n in ("0.0.0.0/8", "198.18.0.0/15"))


def _is_placeholder_host(host: object) -> bool:
    if not isinstance(host, str) or not host:
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False  # a hostname is a real server
    return addr.version == 4 and any(addr in net for net in _PLACEHOLDER_NETS)


def is_stub_server(cfg: dict) -> bool:
    """A panel's notice dressed as a server ("⚠️ Client not supported",
    "Device limit reached: 4"): no proxy outbound at all, or every one points
    at a placeholder address. An outbound whose target can't be parsed counts
    as real — never hide a server over a format we don't know."""
    proxies = [
        o
        for o in cfg.get("outbounds") or []
        if isinstance(o, dict) and o.get("protocol") not in _STUB_IGNORED_PROTOCOLS
    ]
    from happ.servers import _outbound_target  # noqa: PLC0415 — avoid import cycle at module load

    for outbound in proxies:
        target = _outbound_target({"outbounds": [outbound]})
        if target is None or not _is_placeholder_host(target[0]):
            return False
    return True


def _sub_cache_path(sub_id: str) -> Path:
    # sub_id is usually a log-derived digit string or a sha1 hash (both
    # already safe), but a routing.json "subscriptionId" fallback is not
    # validated on the way in — strip anything but word chars/hyphen so a
    # crafted id (e.g. containing "../") can't escape SUB_CACHE_DIR.
    safe_id = re.sub(r"[^\w-]", "_", sub_id)
    return _happmeta().SUB_CACHE_DIR / f"subscription-{safe_id}.json"


def fetch_subscription(sub_id: str, url: str, force: bool = False) -> list[dict]:
    """Server configs from the provider, cached for SUB_MAX_AGE.

    Falls back to the last good cache when the fetch fails or the provider
    answers with the anti-curl stub. force=True skips the fresh-cache early
    return (the Refresh All menu action); the default keeps the SUB_MAX_AGE
    gate the --status path relies on.
    """
    hm = _happmeta()
    if hm.fetch_subscription is not fetch_subscription:
        return hm.fetch_subscription(sub_id, url, force)
    return _fetch_subscription(sub_id, url, force)[0]


SUB_FETCH_TIMEOUT = 15  # seconds per attempt
SUB_FETCH_ATTEMPTS = 2  # OK's panel sometimes hangs, then answers in 0.4 s


def _download_subscription(url: str) -> tuple[object, dict | None]:
    """(parsed JSON, panel info) — retried once on a network failure; a 4xx
    or a non-JSON answer is the panel's final word and isn't."""
    ureq = _happmeta().urllib.request
    req = ureq.Request(url, headers=_headers())
    for attempt in range(SUB_FETCH_ATTEMPTS):
        try:
            with ureq.urlopen(req, timeout=SUB_FETCH_TIMEOUT) as resp:
                data = json.loads(resp.read().decode())
                return data, _parse_sub_info(resp)  # headers only readable while open
        except ureq.HTTPError as e:
            if e.code < 500 or attempt + 1 == SUB_FETCH_ATTEMPTS:
                raise
        except OSError:
            if attempt + 1 == SUB_FETCH_ATTEMPTS:
                raise
    raise AssertionError("unreachable")  # pragma: no cover


def _fetch_error_reason(e: Exception) -> str:
    if isinstance(e, _happmeta().urllib.request.HTTPError):
        return f"HTTP {e.code}"
    reason = getattr(e, "reason", None)  # URLError wrapping the socket error
    if isinstance(reason, Exception):
        e = reason
    if isinstance(e, TimeoutError):
        return "timed out"
    if isinstance(e, ValueError):
        return "not a Happ subscription answer"
    return str(e) or type(e).__name__


def _fetch_subscription(sub_id: str, url: str, force: bool) -> tuple[list[dict], str | None]:
    """fetch_subscription() plus why it didn't update: None when the servers
    are fresh (fetched now or within SUB_MAX_AGE), else a short reason —
    the network error, or the panel's own stub row (device limit)."""
    hm = _happmeta()
    if hm._fetch_subscription is not _fetch_subscription:
        return hm._fetch_subscription(sub_id, url, force)
    cache_path = _sub_cache_path(sub_id)
    try:
        cached = json.loads(cache_path.read_text())
    except OSError, json.JSONDecodeError:
        cached = None
    fallback = cached.get("servers", []) if isinstance(cached, dict) else []

    # Fresh only for THIS url: after a token rotation the record may hold a
    # fresh cache fetched with the old url. Records without "url" predate
    # this scheme and are treated as matching (no mass refetch).
    if (
        not force
        and isinstance(cached, dict)
        and cached.get("url", url) == url
        and time.time() - cached.get("at", 0) < hm.SUB_MAX_AGE
    ):
        return fallback, None

    # the url comes from Happ's log: never let it open file:// or other schemes
    if not url.startswith(("https://", "http://")):
        return fallback, "not an http(s) url"
    try:
        data, info = _download_subscription(url)
    except (OSError, ValueError) as e:
        return fallback, _fetch_error_reason(e)
    if not (isinstance(data, list) and data and isinstance(data[0], dict)):
        return fallback, "not a Happ subscription answer"

    configs = [s for s in data if s.get("outbounds")]
    servers = [s for s in configs if not is_stub_server(s)]
    record: dict[str, Any] = {"at": time.time(), "url": url, "servers": servers}
    error = None
    if not servers:
        # The panel turned us away (unsupported client, device
        # limit): keep the last real servers, remember why.
        record["rejected"] = [str(s.get("remarks") or "") for s in configs]
        error = next((r for r in record["rejected"] if r), "no servers")
        if isinstance(cached, dict) and cached.get("url") == url:
            servers = [s for s in cached.get("servers", []) if not is_stub_server(s)]
            record["servers"] = servers
    if info is not None:
        record["info"] = info
    elif (
        isinstance(cached, dict)
        and cached.get("url") == url
        and isinstance(cached.get("info"), dict)
    ):
        # panel answered without headers — keep the previous info
        record["info"] = cached["info"]
    # configs carry UUIDs and reality keys — fsutil writes 0600
    with contextlib.suppress(OSError):
        fsutil.write_json_atomic(cache_path, record, ensure_ascii=False)
    return servers, error


def _parse_sub_info(resp) -> dict | None:
    """Panel card info from response headers: traffic, expiry, display title.

    'Subscription-Userinfo: upload=0; download=…; total=0; expire=…'
    (total=0 means unlimited; expire is a unix epoch) and 'Profile-Title'
    (some panels base64-encode it with a 'base64:' prefix). Returns None when
    no field parsed; individual fields stay None when missing or malformed.
    """
    info: dict = {"upload": None, "download": None, "total": None, "expire": None, "title": None}
    headers = getattr(resp, "headers", None)
    if headers is None:
        return None
    raw = headers.get("Subscription-Userinfo")
    if raw:
        for part in raw.split(";"):
            key, _, val = part.strip().partition("=")
            if key in ("upload", "download", "total", "expire"):
                with contextlib.suppress(ValueError):
                    info[key] = int(val)  # tolerate malformed values, keep None
    title = headers.get("Profile-Title")
    if title:
        title = title.strip()
        if title.startswith("base64:"):
            try:
                title = base64.b64decode(title[len("base64:") :]).decode("utf-8", errors="replace")
            except ValueError, TypeError:
                title = None
        info["title"] = title or None
    return info if any(v is not None for v in info.values()) else None


def subscription_info(sub_id: str) -> dict | None:
    """Cache-only panel info (traffic/expiry/title) for a provider's
    subscription; None when absent (older caches lack the "info" record)."""
    try:
        cached = json.loads(_sub_cache_path(sub_id).read_text())
    except OSError, json.JSONDecodeError:
        return None
    if not isinstance(cached, dict):
        return None
    info = cached.get("info")
    return info if isinstance(info, dict) else None


def fmt_traffic(bytes_: int | None) -> str:
    """1973660012446 -> '1838 GB' (Happ's GB is 2^30 bytes); None -> '?'."""
    if not isinstance(bytes_, (int, float)) or isinstance(bytes_, bool) or bytes_ < 0:
        return "?"
    gb = bytes_ / 2**30
    if gb >= 100:
        return f"{gb:.0f} GB"
    small = f"{gb:.1f}"
    return f"{small[:-2]} GB" if small.endswith(".0") else f"{small} GB"


def fmt_limit(total: int | None) -> str:
    """Traffic limit: 0 or None means unlimited."""
    if not isinstance(total, (int, float)) or isinstance(total, bool) or total == 0:
        return "∞"
    return fmt_traffic(total)


def fmt_expire(epoch: int | None) -> str:
    """1797232846 -> '14.12.2026'; None -> '?'."""
    if not isinstance(epoch, (int, float)) or isinstance(epoch, bool):
        return "?"
    try:
        return datetime.fromtimestamp(epoch).strftime("%d.%m.%Y")
    except OverflowError, OSError, ValueError:
        return "?"


# path -> ((inode, mtime_ns, size), parsed). One --status run read every
# subscription cache (~1 MB of JSON) twice — freshness check, then the server
# list — ~40 ms of a 3-second tick. Writes go through os.replace, so a new
# file always has a new inode and a stale entry can't match.
_SUB_CACHE_MEMO: dict[Path, tuple[tuple[int, int, int], object]] = {}


def _read_sub_cache(sub_id: str) -> object:
    """Parsed subscription cache file, or None if missing/unreadable."""
    path = _sub_cache_path(sub_id)
    try:
        st = path.stat()
        key = (st.st_ino, st.st_mtime_ns, st.st_size)
        memo = _SUB_CACHE_MEMO.get(path)
        if memo and memo[0] == key:
            return memo[1]
        data = json.loads(path.read_text())
    except OSError, json.JSONDecodeError:
        return None
    _SUB_CACHE_MEMO[path] = (key, data)
    return data


def fetch_subscription_cached(sub_id: str) -> list[dict]:
    """Cache-only read: fresh or stale servers, never touches the network.
    Used on the bar widget's --status path so a 3 s tick never blocks on I/O."""
    cached = _read_sub_cache(sub_id)
    return cached.get("servers", []) if isinstance(cached, dict) else []


def subscription_rejection(sub_id: str) -> list[str]:
    """The stub rows the panel answered the last fetch with, [] if it served."""
    cached = _read_sub_cache(sub_id)
    rejected = cached.get("rejected") if isinstance(cached, dict) else None
    return [r for r in rejected if isinstance(r, str) and r] if isinstance(rejected, list) else []


def _sub_cache_fresh(sub_id: str, url: str) -> bool:
    cached = _read_sub_cache(sub_id)
    try:
        return (
            isinstance(cached, dict)
            and cached.get("url", url) == url  # legacy records without url match
            and time.time() - cached.get("at", 0) < _happmeta().SUB_MAX_AGE
        )
    except AttributeError, TypeError:
        return False


def _subs_refresh_path() -> Path:
    return _happmeta().SUB_CACHE_DIR / "subs-refresh.json"


def _subs_refresh_in_progress() -> bool:
    """True while a refresh attempt started recently — running or just failed.
    Keeps the 3 s status tick from piling up --update-subs workers."""
    try:
        state = json.loads(_subs_refresh_path().read_text())
        return time.time() - state.get("at", 0) < _happmeta().SUBS_REFRESH_RETRY
    except OSError, json.JSONDecodeError, AttributeError, TypeError:
        return False


def _stamp_subs_refresh(failed: dict[str, str] | None = None) -> None:
    with contextlib.suppress(OSError):
        fsutil.write_json_atomic(_subs_refresh_path(), {"at": time.time(), "failed": failed or {}})


def last_subs_failures() -> dict[str, str]:
    """What the previous refresh couldn't update ({name: reason})."""
    try:
        failed = json.loads(_subs_refresh_path().read_text()).get("failed")
    except OSError, json.JSONDecodeError, AttributeError:
        return {}
    return failed if isinstance(failed, dict) else {}


def request_subscription_update() -> None:
    """Fire-and-forget background subscription refresh if any cache is stale."""
    if _subs_refresh_in_progress():
        return
    for sub_id, prov in providers().items():
        if prov.get("url") and not _sub_cache_fresh(sub_id, prov["url"]):
            with contextlib.suppress(OSError):  # a spawn failure must never break --status
                subp = _happmeta().subprocess
                subp.Popen(
                    [sys.executable, str(_happmeta().MANAGER), "--update-subs"],
                    stdout=subp.DEVNULL,
                    stderr=subp.DEVNULL,
                    start_new_session=True,
                )
            return


def update_subscriptions(force: bool = False) -> dict[str, str]:
    """Background entry point: refresh every subscription cache.
    force=True (Refresh All's --update-subs-force) re-fetches even caches
    younger than SUB_MAX_AGE; the default --update-subs run keeps the gate.
    Returns {provider name: why it didn't update} for the manual refresh's
    notification — the old caches stay in use either way."""
    # stamped first, even when fetches fail below: single-flight for the tick
    _stamp_subs_refresh()
    failed: dict[str, str] = {}
    for sub_id, prov in providers().items():
        url = prov.get("url")
        if not url:
            continue
        try:
            # one failing provider must not stop the others
            error = _fetch_subscription(sub_id, url, force)[1]
        except (OSError, AttributeError, ValueError) as e:
            error = _fetch_error_reason(e)
        if error:
            failed[prov.get("name") or sub_id] = error
    _stamp_subs_refresh(failed)
    return failed
