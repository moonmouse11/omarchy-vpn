"""Validation for shared Happ/INCY subscription cache records."""

import math


def normalize_record(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    timestamp = value.get("at")
    if (
        isinstance(timestamp, bool)
        or not isinstance(timestamp, (int, float))
        or not math.isfinite(timestamp)
    ):
        return None
    url = value.get("url")
    if url is not None and not isinstance(url, str):
        return None
    servers = value.get("servers")
    if not isinstance(servers, list) or not all(isinstance(server, dict) for server in servers):
        return None
    return dict(value)
