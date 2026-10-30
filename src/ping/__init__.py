"""Direct latency measurement and shared ping cache (WireGuard/OpenVPN paths).

Happ/Keys use delayping (xray under happd); they still read/write this cache file.
"""

from ping.cache import (
    PING_CACHE,
    PING_MAX_AGE,
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
