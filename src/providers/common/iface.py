import json
import subprocess
import time
from pathlib import Path

import fsutil


def human_bytes(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def iface_traffic(iface: str) -> str | None:
    """RX/TX totals for an interface via `ip -s link` (no root needed).

    Returns "↓ 1.2 MiB  ↑ 3.4 MiB" or None if stats are unavailable.
    """
    counters = _iface_counters(iface)
    if counters is None:
        return None
    rx, tx = counters
    return f"↓ {human_bytes(rx)}  ↑ {human_bytes(tx)}"


RATE_CACHE = Path.home() / ".cache/vpn-manager/iface-rate.json"


def _iface_counters(iface: str) -> tuple[int, int] | None:
    result = subprocess.run(
        ["ip", "-s", "link", "show", "dev", iface],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    lines = result.stdout.splitlines()
    rx = tx = None
    for i, line in enumerate(lines):
        if "RX:" in line and i + 1 < len(lines):
            rx = int(lines[i + 1].split()[0])
        if "TX:" in line and i + 1 < len(lines):
            tx = int(lines[i + 1].split()[0])
    if rx is None or tx is None:
        return None
    return (rx, tx)


def sample_iface_traffic(iface: str) -> None:
    """Record current counters for iface into RATE_CACHE (called by the
    periodic --status tick; best-effort, never raises)."""
    counters = _iface_counters(iface)
    if counters is None:
        return
    rx, tx = counters
    try:
        try:
            cache = json.loads(RATE_CACHE.read_text())
        except OSError, json.JSONDecodeError:
            cache = {}
        if not isinstance(cache, dict):
            cache = {}
        cache[iface] = {"rx": rx, "tx": tx, "at": time.time()}
        fsutil.write_json_atomic(RATE_CACHE, cache)
    except OSError:
        pass


def iface_rate(iface: str | None) -> str | None:
    """Per-second RX/TX, "↓ 1.2 MiB/s ↑ 3.4 KiB/s", or None.

    Read-only: compares the current counters against the sample written by
    the --status tick. The first sample after connect has no predecessor,
    so None until the second tick (~3 s). Counter resets (interface
    recreated) yield None rather than a negative rate."""
    if not iface:
        return None
    counters = _iface_counters(iface)
    if counters is None:
        return None
    try:
        cache = json.loads(RATE_CACHE.read_text())
    except OSError, json.JSONDecodeError:
        return None
    prev = cache.get(iface) if isinstance(cache, dict) else None
    if not isinstance(prev, dict):
        return None
    dt = time.time() - prev.get("at", 0)
    rx_delta = counters[0] - prev.get("rx", 0)
    tx_delta = counters[1] - prev.get("tx", 0)
    if dt <= 0 or rx_delta < 0 or tx_delta < 0:
        return None
    if rx_delta == 0 and tx_delta == 0:
        return None
    return f"↓ {human_bytes(rx_delta / dt)}/s ↑ {human_bytes(tx_delta / dt)}/s"
