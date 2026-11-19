"""Fetch provider subscription URLs into vpn-manager cache files."""

from __future__ import annotations

import base64
import contextlib
import json
import time
import urllib
from pathlib import Path
from typing import Any, cast, override

import fsutil
import lazyimports  # noqa: F401 — lazy urllib.request
from happ.constants import SUB_MAX_AGE
from happ.subscriptions import is_stub_server
from subscription.cache import normalize_record

MAX_SUBSCRIPTION_BYTES = 16 * 1024 * 1024


def _open_https(request, timeout: float):
    """Open HTTPS without ever following a redirect to plaintext HTTP."""
    if not request.full_url.lower().startswith("https://"):
        raise ValueError("HTTPS required")

    class HTTPSOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
        @override
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if not newurl.lower().startswith("https://"):
                raise ValueError("HTTPS required")
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    return urllib.request.build_opener(HTTPSOnlyRedirectHandler()).open(request, timeout=timeout)


def download_subscription(
    url: str, headers: dict[str, str], *, open_https=None
) -> tuple[object, dict | None]:
    """(parsed JSON body, panel info) — retried once on network failure."""
    if not url.lower().startswith("https://"):
        raise ValueError("HTTPS required")
    req = urllib.request.Request(url, headers=headers)  # noqa: S310 — HTTPS checked above
    opener = open_https or _open_https
    timeout = 15
    attempts = 2
    for attempt in range(attempts):
        try:
            with opener(req, timeout) as resp:
                payload = resp.read(MAX_SUBSCRIPTION_BYTES + 1)
                if len(payload) > MAX_SUBSCRIPTION_BYTES:
                    raise ValueError("subscription exceeds 16 MiB size limit")
                data = json.loads(payload.decode())
                return data, _parse_sub_info(resp)
        except urllib.error.HTTPError as e:
            if e.code < 500 or attempt + 1 == attempts:
                raise
        except OSError:
            if attempt + 1 == attempts:
                raise
    raise AssertionError("unreachable")  # pragma: no cover


def _parse_sub_info(resp) -> dict | None:
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
                    info[key] = int(val)
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


def _fetch_error_reason(e: Exception) -> str:
    if isinstance(e, urllib.error.HTTPError):
        return f"HTTP {e.code}"
    reason = getattr(e, "reason", None)
    if isinstance(reason, Exception):
        e = reason
    if isinstance(e, TimeoutError):
        return "timed out"
    if isinstance(e, ValueError):
        return "HTTPS required" if str(e) == "HTTPS required" else "not a subscription answer"
    return str(e) or type(e).__name__


def fetch_subscription_to_cache(
    cache_path: Path,
    url: str,
    headers: dict[str, str],
    *,
    force: bool = False,
    max_age: float = SUB_MAX_AGE,
    open_https=None,
) -> tuple[list[dict], str | None]:
    """Return (server configs, error). error is None when cache is fresh."""
    try:
        cached = normalize_record(json.loads(cache_path.read_text()))
    except OSError, json.JSONDecodeError:
        cached = None
    fallback = cast(list[dict], cached["servers"]) if cached is not None else []

    if (
        not force
        and cached is not None
        and cached.get("url", url) == url
        and time.time() - cast(float, cached["at"]) < max_age
    ):
        return fallback, None

    if not url.lower().startswith("https://"):
        return fallback, "HTTPS required"
    try:
        data, info = download_subscription(url, headers, open_https=open_https)
    except (OSError, ValueError) as e:
        return fallback, _fetch_error_reason(e)
    if not (isinstance(data, list) and data and all(isinstance(s, dict) for s in data)):
        return fallback, "not a subscription answer"

    configs = [s for s in data if s.get("outbounds")]
    servers = [s for s in configs if not is_stub_server(s)]
    record: dict[str, Any] = {"at": time.time(), "url": url, "servers": servers}
    error = None
    if not servers:
        record["rejected"] = [str(s.get("remarks") or "") for s in configs]
        error = next((r for r in record["rejected"] if r), "no servers")
        if cached is not None and cached.get("url") == url:
            servers = [s for s in fallback if not is_stub_server(s)]
            record["servers"] = servers
    if info is not None:
        record["info"] = info
    elif cached is not None and cached.get("url") == url and isinstance(cached.get("info"), dict):
        record["info"] = cached["info"]
    with contextlib.suppress(OSError):
        fsutil.write_json_atomic(cache_path, record, ensure_ascii=False)
    return servers, error
