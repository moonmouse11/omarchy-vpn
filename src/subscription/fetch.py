"""Fetch provider subscription URLs into vpn-manager cache files."""

from __future__ import annotations

import base64
import contextlib
import json
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError

import fsutil
from happ.constants import SUB_MAX_AGE
from happ.subscriptions import is_stub_server


def download_subscription(url: str, headers: dict[str, str]) -> tuple[object, dict | None]:
    """(parsed JSON body, panel info) — retried once on network failure."""
    import lazyimports  # noqa: PLC0415 — urllib must stay lazy on import

    ureq = lazyimports.urllib.request
    req = ureq.Request(url, headers=headers)
    timeout = 15
    attempts = 2
    for attempt in range(attempts):
        try:
            with ureq.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode())
                return data, _parse_sub_info(resp)
        except ureq.HTTPError as e:
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
    if isinstance(e, HTTPError):
        return f"HTTP {e.code}"
    reason = getattr(e, "reason", None)
    if isinstance(reason, Exception):
        e = reason
    if isinstance(e, TimeoutError):
        return "timed out"
    if isinstance(e, ValueError):
        return "not a subscription answer"
    return str(e) or type(e).__name__


def fetch_subscription_to_cache(
    cache_path: Path,
    url: str,
    headers: dict[str, str],
    *,
    force: bool = False,
    max_age: float = SUB_MAX_AGE,
) -> tuple[list[dict], str | None]:
    """Return (server configs, error). error is None when cache is fresh."""
    try:
        cached = json.loads(cache_path.read_text())
    except OSError, json.JSONDecodeError:
        cached = None
    fallback = cached.get("servers", []) if isinstance(cached, dict) else []

    if (
        not force
        and isinstance(cached, dict)
        and cached.get("url", url) == url
        and time.time() - cached.get("at", 0) < max_age
    ):
        return fallback, None

    if not url.startswith(("https://", "http://")):
        return fallback, "not an http(s) url"
    try:
        data, info = download_subscription(url, headers)
    except (OSError, ValueError) as e:
        return fallback, _fetch_error_reason(e)
    if not (isinstance(data, list) and data and isinstance(data[0], dict)):
        return fallback, "not a subscription answer"

    configs = [s for s in data if s.get("outbounds")]
    servers = [s for s in configs if not is_stub_server(s)]
    record: dict[str, Any] = {"at": time.time(), "url": url, "servers": servers}
    error = None
    if not servers:
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
        record["info"] = cached["info"]
    with contextlib.suppress(OSError):
        fsutil.write_json_atomic(cache_path, record, ensure_ascii=False)
    return servers, error
