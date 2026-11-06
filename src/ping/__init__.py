"""Direct latency measurement and shared ping cache (WireGuard/OpenVPN paths).

Happ/Keys use delayping (xray under happd); they still read/write this cache file.
"""

import sys
from pathlib import Path

from ping.cache import (
    ping_at,
    ping_key,
    ping_mark,
    ping_ms,
    ping_status,
    provider_ping_summary,
    read_pings,
)
from ping.measure import PING_TIMEOUT, measure_ping, uplink_interface
from ping.targets import happ_ping_targets as ping_targets

_DEFAULT_PING_CACHE = Path.home() / ".cache/vpn-manager/happ-ping.json"


def __getattr__(name: str):
    if name == "PING_CACHE":
        hm = sys.modules.get("happmeta")
        return (
            hm.PING_CACHE if hm is not None and hasattr(hm, "PING_CACHE") else _DEFAULT_PING_CACHE
        )
    if name == "PING_MAX_AGE":
        hm = sys.modules.get("happmeta")
        return hm.PING_MAX_AGE if hm is not None and hasattr(hm, "PING_MAX_AGE") else 86400
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "PING_CACHE",
    "PING_MAX_AGE",
    "PING_TIMEOUT",
    "measure_ping",
    "ping_at",
    "ping_key",
    "ping_mark",
    "ping_ms",
    "ping_status",
    "ping_targets",
    "provider_ping_summary",
    "read_pings",
    "uplink_interface",
]
