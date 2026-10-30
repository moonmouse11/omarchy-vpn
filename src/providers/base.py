import contextlib
import json
import os
import signal
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

import fsutil

type PingTarget = tuple[str, str, int] | tuple[str, str, int, bool]

# The one root entry point for WireGuard/AmneziaWG/OpenVPN (scripts/omarchy-vpn-helper,
# installed by install.sh): profile names only, never paths — the old sudoers rule
# (`wg-quick *`, `cp * /etc/wireguard/*`, `cat …`, `kill`) was root for any process.
HELPER = "/usr/local/bin/omarchy-vpn-helper"
# config directory -> the helper's KIND
HELPER_KINDS = {
    "/etc/wireguard": "wg",
    "/etc/amnezia/amneziawg": "awg",
    "/etc/openvpn/client": "ovpn",
}


_helper_slot: list[subprocess.Popen[str] | None] = [None]


def terminate_registered_subprocesses() -> None:
    """Stop a long `run_helper()` still in flight (switch superseded it)."""
    proc = _helper_slot[0]
    _helper_slot[0] = None
    if proc is None or proc.poll() is not None:
        return
    with contextlib.suppress(OSError, ProcessLookupError):
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(OSError, ProcessLookupError):
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=1)


def run_helper(*args: str, stdin: str | None = None, timeout: float = 60) -> tuple[int, str]:
    """`sudo -n omarchy-vpn-helper ARGS` → (returncode, stdout+stderr).

    Polls instead of subprocess.run so SIGTERM from a superseding switch can
    run terminate_registered_subprocesses() and drop a stuck sudo/awg-quick."""
    try:
        proc = subprocess.Popen(
            ["sudo", "-n", HELPER, *args],
            stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            start_new_session=True,
        )
    except OSError as e:
        return 1, str(e)
    _helper_slot[0] = proc
    try:
        if stdin is not None and proc.stdin:
            proc.stdin.write(stdin)
            proc.stdin.close()
        deadline = time.monotonic() + timeout
        while proc.poll() is None:
            if time.monotonic() >= deadline:
                terminate_registered_subprocesses()
                return 1, "timeout"
            time.sleep(0.05)
        if proc.stdout is None:
            return proc.returncode or 0, ""
        out = proc.stdout.read()
        return proc.returncode or 0, out.strip()
    except OSError as e:
        terminate_registered_subprocesses()
        return 1, str(e)
    finally:
        _helper_slot[0] = None


def read_config_text(path) -> str | None:
    """Text of a provider config: direct read first, else the helper's
    `endpoints` (configs are root:0600) — only the Endpoint/remote lines and
    section headers, never the keys, which is all the ping and the kill
    switch whitelist read. None when neither works."""
    p = Path(path)
    try:
        return p.read_text(errors="replace")
    except OSError:
        pass
    kind = HELPER_KINDS.get(str(p.parent))
    if kind is None:
        return None
    code, out = run_helper("endpoints", kind, p.stem, timeout=10)
    return out if code == 0 else None


@dataclass
class VPNConnection:
    name: str
    provider: str
    active: bool
    interface: str | None = None
    config_path: str | None = None
    uuid: str | None = None  # NetworkManager connection UUID
    # Happ: which subscription this server came from. Server names are only
    # unique within one subscription, so (subscription_id, name) is the
    # real identity — two providers commonly both ship a "🇩🇪 Germany".
    subscription_id: str | None = None
    subscription_name: str | None = None

    @property
    def label(self) -> str:
        """'Happ · Provider C: 🇩🇪 Germany', or 'WireGuard: nl' without a subscription."""
        if self.subscription_name:
            return f"{self.provider} · {self.subscription_name}: {self.name}"
        return f"{self.provider}: {self.name}"


@dataclass
class ActionResult:
    success: bool
    message: str


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


class VPNProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Display name of the provider, e.g. 'WireGuard'"""
        ...

    @abstractmethod
    def connections(self) -> list[VPNConnection]:
        """Return all known connections (active and inactive)"""
        ...

    @abstractmethod
    def connect(self, connection: VPNConnection) -> ActionResult: ...

    @abstractmethod
    def disconnect(self, connection: VPNConnection) -> ActionResult: ...

    @abstractmethod
    def import_config(self, path: str) -> ActionResult:
        """Import a config file and register it as a new connection"""
        ...

    def ping_targets(self) -> list[PingTarget]:
        """(connection name, host, port[, icmp_only]) for ping measurement.
        WireGuard/AmneziaWG pass icmp_only=True (UDP endpoints). The shared
        ping cache and ✓/✗ labels are name-keyed."""
        return []

    def toggle_autostart(self, connection: VPNConnection) -> ActionResult:
        return ActionResult(False, f"{self.name}: autostart not supported")

    def delete_config(self, connection: VPNConnection) -> ActionResult:
        return ActionResult(False, f"{self.name}: config delete not supported")
