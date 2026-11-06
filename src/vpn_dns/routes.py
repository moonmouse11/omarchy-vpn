"""Cached, local DNS-route observations. Only the background/check path probes routes."""

from __future__ import annotations

import contextlib
import fcntl
import ipaddress
import json
import os
import subprocess
import time
from pathlib import Path

import fsutil
import killswitch
from app.spawn import spawn_manager
from providers.base import VPNConnection

CACHE = Path.home() / ".cache/vpn-manager/dns-route.json"
MAX_AGE = 60
LAN_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
    )
)


def _read() -> dict:
    try:
        data = json.loads(CACHE.read_text())
        return data if isinstance(data, dict) else {}
    except OSError, ValueError:
        return {}


def read_cache() -> dict | None:
    data = _read()
    at = data.get("at")
    if (
        not isinstance(at, (int, float))
        or not 0 <= time.time() - at < MAX_AGE
        or data.get("pending")
        or any(not isinstance(data.get(key), list) for key in ("interfaces", "lan", "unknown"))
    ):
        return None
    if any(not isinstance(item, str) for key in ("interfaces", "unknown") for item in data[key]):
        return None
    if any(
        not isinstance(item, dict)
        or not isinstance(item.get("ip"), str)
        or not isinstance(item.get("interface"), str)
        for item in data["lan"]
    ):
        return None
    return data


def _request_update() -> None:
    try:
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(CACHE.with_suffix(".lock"), os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            data = _read()
            if data.get("pending") and time.time() - float(data.get("at", 0)) < MAX_AGE:
                return
            fsutil.write_json_atomic(CACHE, {"at": time.time(), "pending": True})
            spawn_manager("--dns-route-update")
        finally:
            os.close(fd)
    except OSError, ValueError, TypeError:
        pass  # An unavailable observation must stay unknown, not break --status.


def warning(interface: str | None) -> str | None:
    data = read_cache()
    if data is None or (interface is not None and interface not in data["interfaces"]):
        _request_update()
        return "Warning: DNS route unverified — checking configured upstream resolvers"
    if data["lan"]:
        addresses = ", ".join(f"{item['ip']} via {item['interface']}" for item in data["lan"])
        return (
            f"Warning: configured LAN DNS ({addresses}) can bypass the tunnel;"
            " LAN access is allowed — this does not prove a leak"
        )
    if data["unknown"]:
        return "Warning: DNS route unverified for " + ", ".join(data["unknown"])
    return None


def update(active: list[VPNConnection]) -> None:
    interfaces = sorted({conn.interface for conn in active if conn.interface})
    lan: list[dict] = []
    unknown: list[str] = []
    resolvers = killswitch.system_resolvers()
    for server in resolvers:
        address = ipaddress.ip_address(server)
        if not any(address in network for network in LAN_NETWORKS):
            continue
        try:
            result = subprocess.run(
                ["ip", "-json", "route", "get", server],
                capture_output=True,
                text=True,
                timeout=1,
                check=False,
            )
            routes = json.loads(result.stdout) if result.returncode == 0 else []
            dev = routes[0].get("dev") if isinstance(routes, list) and routes else None
            if not dev or dev == "lo":
                unknown.append(server)
            elif dev not in interfaces:
                lan.append({"ip": server, "interface": dev})
        except OSError, ValueError, TypeError, AttributeError, subprocess.TimeoutExpired:
            unknown.append(server)
    if not resolvers:
        unknown.append("system upstream DNS unavailable")
    with contextlib.suppress(OSError):
        fsutil.write_json_atomic(
            CACHE,
            {"at": time.time(), "interfaces": interfaces, "lan": lan, "unknown": unknown},
        )
