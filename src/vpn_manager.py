#!/usr/bin/env python3
"""
omarchy-vpn — entry point
Usage:
  vpn_manager.py --status   Output JSON status for the omarchy-shell bar widget
  vpn_manager.py --menu     Open the interactive menu (omarchy.menu)
"""

import argparse
import contextlib
import fcntl
import getpass
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import config
import dnsleak
import fsutil
import happmeta
import ipinfo
import ipsources
import ipv6guard
import killswitch
import logutil
import notifyutil
import providers.happ as happ_provider
import reputation
import settings_tui
import speedtest
from providers import ALL_PROVIDERS
from providers.base import (
    ActionResult,
    VPNConnection,
    iface_rate,
    iface_traffic,
    sample_iface_traffic,
)
from providers.happ import run_keeper as run_happ_keeper
from providers.keys import KeysProvider
from providers.keys import run_keeper as run_keys_keeper

PLUGIN_ID = "omarchy-vpn"  # omarchy-shell plugin id == its IPC target (plugin/manifest.json)


def visible_providers() -> list:
    """Providers not hidden in the user config."""
    cfg = config.load_config()
    return [p for p in ALL_PROVIDERS if cfg.provider_visible(p.name)]


def active_connections(providers=None) -> list[VPNConnection]:
    return [
        conn
        for provider in (providers or visible_providers())
        for conn in provider.connections()
        if conn.active
    ]


NO_VPN = "direct"  # pseudo-connection key for the ipinfo cache when no VPN is up
BACK_LABEL = "‹ Back"


# ── Status ────────────────────────────────────────────────────────────────────


def get_status() -> dict:
    """Aggregate ALL active connections across providers.

    Waybar-style classes: "vpn-connected" + "vpn-<provider>" per active provider,
    "vpn-disconnected" when nothing is up. Tooltip lists every active
    connection with per-interface traffic stats.
    """
    cfg = config.load_config()
    active = active_connections()

    if not active:
        return {
            "text": " VPN",
            "tooltip": "VPN: not connected",
            "class": "vpn-disconnected",
            "panel": panel_state(active, cfg),
        }

    # before the tooltip loop: it saves a fresh traffic sample, and a rate
    # read after that compares against itself (~0 s apart) — the panel's
    # speed came out empty
    panel = panel_state(active, cfg)
    extra = f" (+{len(active) - 1})" if len(active) > 1 else ""
    classes = ["vpn-connected"]
    tooltip = []
    for conn in active:
        classes.append(f"vpn-{conn.provider.lower()}")
        line = conn.label
        if conn.interface:
            # rate first (units per second, like the menu), then totals —
            # plain arrows on both rows confused "B/s" with "MiB"
            rate = iface_rate(conn.interface)
            traffic = iface_traffic(conn.interface)
            if rate:
                line += f"\n  {rate}"
            if traffic:
                line += f"\n  {traffic} total"
            sample_iface_traffic(conn.interface)  # next tick can show a rate
        tooltip.append(line)

    if cfg.exit_ip_enabled:
        exit_line = ipinfo.status_line(active[0].name, cfg.exit_ip_max_age)
        if exit_line:
            tooltip.append(exit_line)
        else:
            request_ip_update(active[0].name)

    first = active[0]
    return {
        "text": f" {first.label}{extra}",
        "tooltip": "\n".join(tooltip),
        "class": classes,
        "panel": panel,
    }


def _badge(badge_id: str, label: str, state: str, hint: str) -> dict:
    """One protection badge. state: "ok" | "bad" | "unknown"."""
    return {"id": badge_id, "label": label, "state": state, "hint": hint}


def _exit_badge(conn: VPNConnection, max_age: int) -> dict:
    """Does the exit IP sit where the server says it is? Cache-only (the
    tooltip path schedules the lookup); expected country as in the DNS
    leak test: the flag in the name, else the sweep's entry country."""
    cache = ipinfo.read_cache()
    if cache is None or not ipinfo.is_fresh(cache, conn.name, max_age):
        return _badge("exit", "Exit: checking", "unknown", "Looking up the public exit IP")
    country = (cache.get("country_code") or "").upper()
    flag = ipinfo.flag_emoji(country)
    ip = cache.get("ip") or "?"
    expected = _name_flag_country(conn.name) or reputation.country_of(conn.name)
    if not expected or not country:
        return _badge(
            "exit", f"Exit {flag}".strip(), "unknown", f"Exit IP {ip}; nothing to compare"
        )
    if _exit_fits(expected, country):
        return _badge("exit", f"Exit {flag}", "ok", f"Exit IP {ip} is where the server says")
    return _badge(
        "exit",
        f"Exit {flag} ≠ {ipinfo.flag_emoji(expected)}",
        "bad",
        f"Exit IP {ip} is not in the server's country — geo databases can disagree; "
        "run the DNS leak test for a second opinion",
    )


def _dns_badge(conn: VPNConnection) -> dict:
    record = _read_dns_verdict(conn.name)
    if record is None or record.get("leaked") is None:
        return _badge("dns", "DNS: untested", "unknown", "Run the DNS leak test for this server")
    if record["leaked"]:
        return _badge("dns", "DNS leaks", "bad", str(record.get("summary") or ""))
    return _badge("dns", "DNS private", "ok", str(record.get("summary") or ""))


PROTECTION_CHECKS = ("exit", "dns", "ipv6")


# The bar label's labelFormat placeholders (plugin/Widget.qml fills them).
LABEL_FIELDS = (
    "label", "provider", "subscription", "server", "count", "state",
    "exit_ip", "exit_country", "exit_flag",
    "rate", "down", "up", "total", "total_down", "total_up",
    "ping", "protocol", "interface", "sub_traffic", "sub_expire",
    "dns", "ipv6", "killswitch",
)  # fmt: skip


def _split_arrows(text: str) -> tuple[str, str]:
    """ "↓ 3 KiB/s ↑ 4 KiB/s" -> ("3 KiB/s", "4 KiB/s"); ("", "") when absent."""
    down, _, up = text.partition("↑")
    return down.replace("↓", "").strip(), up.strip()


def label_fields(
    active: list[VPNConnection], title: str, badges: list[dict], *, rate: str, total: str, cfg
) -> dict[str, str]:
    """Every value a bar label template can show, as display strings — ""
    when unknown, so the template drops it with its separator. Cache reads
    only: the 3 s tick pays for these (the subscription parse is memoized)."""
    fields = dict.fromkeys(LABEL_FIELDS, "")
    fields["state"] = title
    by_id = {b["id"]: b["label"] for b in badges}
    fields["killswitch"] = by_id.get("killswitch", "")
    if not active:
        return fields
    first = active[0]
    fields.update(
        label=first.label,
        provider=first.provider,
        subscription=first.subscription_name or "",
        server=first.name,
        count=str(len(active)),
        interface=first.interface or "",
        dns=by_id.get("dns", ""),
        ipv6=by_id.get("ipv6", ""),
        rate=rate,
        total=total,
    )
    fields["down"], fields["up"] = _split_arrows(rate)
    fields["total_down"], fields["total_up"] = _split_arrows(total)
    cache = ipinfo.read_cache()
    if cache and ipinfo.is_fresh(cache, first.name, cfg.exit_ip_max_age):
        country = (cache.get("country_code") or "").upper()
        fields.update(
            exit_ip=str(cache.get("ip") or ""),
            exit_country=country,
            exit_flag=ipinfo.flag_emoji(country),
        )
    ms = happmeta.ping_ms(first.name)
    if ms is not None:
        fields["ping"] = f"{round(ms)} ms"
    fields["protocol"] = first.provider
    if first.provider == "Happ":
        server_cfg = happmeta.resolve_config(
            first.name, allow_fetch=False, provider_id=first.subscription_id
        )
        if server_cfg:
            fields["protocol"] = happmeta.protocol_label(server_cfg) or first.provider
    info = happmeta.subscription_info(first.subscription_id) if first.subscription_id else None
    if info:
        used = happmeta.fmt_traffic(info.get("download"))
        if used != "?":
            fields["sub_traffic"] = f"{used} / {happmeta.fmt_limit(info.get('total'))}"
        expire = happmeta.fmt_expire(info.get("expire"))
        if expire != "?":
            fields["sub_expire"] = expire
    return fields


def _killswitch_unsupported(active: list[VPNConnection]) -> bool:
    """A NetworkManager connection is up: the kill switch has no rules for
    it (endpoints not parsed) and is suspended, so it isn't offered or shown."""
    return any(c.provider not in ("Happ", *KILLSWITCH_PROVIDERS) for c in active)


def panel_state(active: list[VPNConnection], cfg) -> dict:
    """What the bar panel draws: a hero (state, connection, exit) and the
    protection badges. Built from caches and cheap probes only — it rides
    on the 3 s --status tick (the kill switch via its 30 s state cache)."""
    ks_on = killswitch.cached_is_enabled()
    ipv6_off = ipv6guard.is_disabled()
    ks_badge = (
        _badge("killswitch", "Kill switch on", "ok", "Traffic outside the tunnel is blocked")
        if ks_on
        else _badge(
            "killswitch", "Kill switch off", "unknown", "Nothing stops a leak if the tunnel drops"
        )
    )
    if not active:
        return {
            "connected": False,
            "state": "blocked" if ks_on else "off",
            "title": "Traffic blocked" if ks_on else "Not protected",
            "meta": "Kill switch holds traffic until a VPN connects" if ks_on else "VPN is off",
            "detail": "",
            "exit_ip": "",
            "rate": "",
            "total": "",
            "badges": [ks_badge],
            "fields": label_fields(
                [],
                "Traffic blocked" if ks_on else "Not protected",
                [ks_badge],
                rate="",
                total="",
                cfg=cfg,
            ),
        }
    first = active[0]
    badges = [
        _exit_badge(first, cfg.exit_ip_max_age),
        _dns_badge(first),
        _badge("ipv6", "IPv6 blocked", "ok", "IPv6 is off while the VPN is up")
        if ipv6_off
        else _badge("ipv6", "IPv6 leaks", "bad", "IPv6 is on and bypasses the tunnel"),
    ]
    if not _killswitch_unsupported(active):
        badges.append(ks_badge)
    if first.provider == "Happ" and happ_provider.app_owns_connection():
        badges.append(
            _badge(
                "happ_app",
                "Happ app connection",
                "unknown",
                "Started in the Happ app, not by this plugin — use one or the other",
            )
        )
    # the pill names the provider: "Happ · ARTEMIDA: 🇩🇪 X" / "WireGuard: nl" -> the rest
    meta = first.label.removeprefix(f"{first.provider} · ").removeprefix(f"{first.provider}: ")
    cache = ipinfo.read_cache()
    exit_ip = ""
    if cache and ipinfo.is_fresh(cache, first.name, cfg.exit_ip_max_age):
        exit_ip = f"{cache.get('ip')} {ipinfo.flag_emoji(cache.get('country_code'))}".strip()
    detail = first.provider + (f" +{len(active) - 1}" if len(active) > 1 else "")
    # "Protected" is earned, not assumed: every check (not the kill switch,
    # a preference) must have passed — an untested DNS keeps it "Unverified"
    checks = [b["state"] for b in badges if b["id"] in PROTECTION_CHECKS]
    if "bad" in checks:
        state, title = "at_risk", "At risk"
    elif all(c == "ok" for c in checks):
        state, title = "protected", "Protected"
    else:
        state, title = "unverified", "Unverified"
    rate = (iface_rate(first.interface) or "") if first.interface else ""
    total = (iface_traffic(first.interface) or "") if first.interface else ""
    return {
        "connected": True,
        "state": state,
        "title": title,
        "meta": meta,
        "detail": detail,
        "exit_ip": exit_ip,
        "rate": rate,
        "total": total,
        "badges": badges,
        "fields": label_fields(active, title, badges, rate=rate, total=total, cfg=cfg),
    }


def request_ip_update(connection_name: str):
    """Fire-and-forget background exit-IP refresh (never blocks the bar)."""
    subprocess.Popen(
        [sys.executable, str(Path(__file__)), "--update-ip", connection_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


# ── Menu actions ──────────────────────────────────────────────────────────────


SWITCH_LOCK = Path.home() / ".cache/vpn-manager/switch.lock"
PREEMPT_GRACE = 2.0  # s for a superseded switch to stop on SIGTERM before SIGKILL
PREEMPT_WAIT = 3.0  # s more for the lock after SIGKILL
PROC = Path("/proc")
# background checks of the connection being left: their answers would
# describe the old server (or time out on a dead one) — killed on a switch.
# Not --update-reputation/--update-subs: those don't depend on which server is up.
CHECK_FLAGS = ("--dns-autotest", "--dns-leak-test", "--update-ip", "--update-ping")


class SwitchBusy(Exception):
    """Another connect/disconnect holds SWITCH_LOCK and won't let go."""


class SwitchCancelled(BaseException):
    """This switch was superseded by a newer one (SIGTERM from its switch_lock).
    BaseException, like KeyboardInterrupt: a provider's `except Exception`
    must not swallow it and carry on connecting."""


class CheckCancelled(BaseException):
    """A DNS leak test stopped by a switch (_abort_checks)."""


def _lock_holder(fd: int) -> tuple[int | None, str]:
    """(pid, action) written by the holder: "PID\naction"."""
    os.lseek(fd, 0, os.SEEK_SET)
    text = os.read(fd, 1024).decode(errors="replace").strip()
    pid_text, _, action = text.partition("\n")
    if pid_text.isdigit():
        return int(pid_text), action.strip() or "another switch"
    return None, text or "another switch"


def _our_process(pid: int, flags: tuple[str, ...] | None = None) -> bool:
    """pid is this program (vpn_manager.py), optionally run with one of flags."""
    try:
        argv = (PROC / str(pid) / "cmdline").read_bytes().split(b"\0")
    except OSError:
        return False
    args = [a.decode(errors="replace") for a in argv if a]
    script = next((i for i, a in enumerate(args) if a.endswith("vpn_manager.py")), None)
    if script is None:
        return False
    return flags is None or (len(args) > script + 1 and args[script + 1] in flags)


def _try_flock(fd: int) -> bool:
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def _wait_flock(fd: int, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while True:
        if _try_flock(fd):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def _preempt(fd: int, pid: int | None) -> bool:
    """Stop the switch holding the lock and take it. SIGTERM first (it
    unwinds through SwitchCancelled); SIGKILL if it doesn't let go — a
    holder stuck inside getaddrinfo only sees a Python signal handler once
    the C call returns. Never this process (a nested switch_lock) and never
    something that isn't ours."""
    if pid is None or pid == os.getpid() or not _our_process(pid):
        return False
    for sig, wait in ((signal.SIGTERM, PREEMPT_GRACE), (signal.SIGKILL, PREEMPT_WAIT)):
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            pass
        except PermissionError:
            return False
        if _wait_flock(fd, wait):
            return True
    return False


def _abort_checks() -> None:
    """SIGTERM every background check of the connection being left (CHECK_FLAGS)."""
    me = os.getpid()
    try:
        pids = [int(p.name) for p in PROC.iterdir() if p.name.isdigit()]
    except OSError:
        return
    for pid in pids:
        if pid != me and _our_process(pid, CHECK_FLAGS):
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGTERM)
                logutil.log(f"switch: aborted check pid {pid}")


def _cancel_switch(signum, frame) -> None:
    raise SwitchCancelled


@contextlib.contextmanager
def switch_lock(action: str):
    """One switch at a time, whoever starts it (menu, panel, shortcut) —
    and the newest one wins.

    A connect can block for minutes (resolving endpoints through a dead
    tunnel), and refusing the next click ("Already switching") left the
    user stuck on a server without internet, unable to switch or even
    disconnect (2026-10-13). So a new switch supersedes the running one:
    it stops the holder (_preempt) and takes the lock; the holder unwinds
    through SwitchCancelled and stays silent. Before that, repeated clicks
    queued up and ran nine connects in the same second. flock, not a pid
    file: the kernel drops it when the holder dies, so a crash (or the
    SIGKILL) can't leave a stale lock. Taking it also stops the checks of
    the connection being left (_abort_checks)."""
    SWITCH_LOCK.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(SWITCH_LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if not _try_flock(fd):
            pid, holder = _lock_holder(fd)
            if not _preempt(fd, pid):
                raise SwitchBusy(holder)
            logutil.log(f"switch superseded: {holder} -> {action}")
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, f"{os.getpid()}\n{action}".encode())
        _abort_checks()
        previous = signal.signal(signal.SIGTERM, _cancel_switch)
        try:
            yield
        finally:
            signal.signal(signal.SIGTERM, previous)
    finally:
        os.close(fd)  # releases the flock


PING_LOCK = Path.home() / ".cache/vpn-manager/ping.lock"
_held_locks: list[int] = []


def _single_flight(path: Path) -> bool:
    """Hold an flock on path for the rest of this process; False if another
    process already holds it. Seen 2026-10-13: seven --update-ping sweeps at
    once, each spawned by a 3 s tick before the first one could finish."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    if not _try_flock(fd):
        os.close(fd)
        return False
    _held_locks.append(fd)  # released when the process exits
    return True


def _busy(e: SwitchBusy) -> ActionResult:
    logutil.log(f"switch refused, busy: {e}")
    return ActionResult(False, f"Already switching ({e}) — wait for it to finish")


def _cancelled(action: str) -> ActionResult:
    # the newer switch reports for itself; a second bubble would only confuse
    logutil.log(f"switch cancelled, superseded: {action}")
    return ActionResult(False, "")


def guarded_connect(provider, connection: VPNConnection) -> ActionResult:
    """_guarded_connect() under SWITCH_LOCK — the entry point for every connect."""
    action = f"connecting to {provider.name}: {connection.name}"
    try:
        with switch_lock(action):
            return _guarded_connect(provider, connection)
    except SwitchBusy as e:
        return _busy(e)
    except SwitchCancelled:
        return _cancelled(action)


KILLSWITCH_PROVIDERS = ("WireGuard", "AmneziaWG", "OpenVPN", "VLESS", "Shadowsocks")


def _killswitch_wanted(provider, enabled: bool) -> bool:
    """Whether this connect runs under the kill switch's rules (the rest —
    NetworkManager — suspends it: its endpoints aren't parsed)."""
    mode = killswitch.mode()
    if provider.name == "Happ":
        return enabled or mode in ("happ", "all")
    return provider.name in KILLSWITCH_PROVIDERS and mode == "all"


def _killswitch_targets(
    provider, connection: VPNConnection, cached_only: bool = False
) -> tuple[list[str], list[str]]:
    """(server IPs, tunnel interfaces) the rules must let through for this
    connect. cached_only: no DNS lookups, last known addresses only."""
    if provider.name != "Happ":
        return _killswitch_all_targets(cached_only=cached_only)
    # Under an enabled killswitch detect() finds nothing pre-connect (no
    # established xray sessions yet), so resolve the target server up front
    # and whitelist it explicitly — otherwise xray is blocked from reaching
    # it and the tunnel comes up dead. Cache-only: a menu click must never
    # block on a subscription fetch (the background --update-subs keeps the
    # caches fresh). Every balancer member, not just the first: xray may
    # dial any of them.
    endpoints = happmeta.server_endpoints(
        connection.name, allow_fetch=False, provider_id=connection.subscription_id
    )
    if not endpoints:
        return [], []
    # + subscription hosts: refreshing them goes through xray and is often
    # routed `direct` (Russian-hosted), which the killswitch blocks
    ips = killswitch.resolve_endpoint_ips(
        [(connection.name, host, port) for host, port in endpoints]
        + happmeta.subscription_targets(),
        cached_only=cached_only,
    )
    return ips, []


def _killswitch_apply(provider, ips: list[str], ifaces: list[str], dns: list[str]):
    if provider.name == "Happ":
        return killswitch.resume_for_happ(extra_ips=ips, dns=dns)
    return killswitch.enable(extra_ips=ips, ifaces=ifaces, dns=dns)


def _guarded_connect(provider, connection: VPNConnection) -> ActionResult:
    """Connect with killswitch interplay.

    Under the kill switch (_killswitch_wanted) the rules go in twice. Before
    the connect: the server's addresses plus port 53 to the system resolvers
    — the one hole, so endpoint hostnames resolve (ours, and wg-quick's
    Endpoint). After it: the same rules without that hole, so DNS leaves only
    through the tunnel, xray's mark or the LAN. The hole is closed in a
    `finally`: an early return or an exception must never leave it open.
    Other providers (NetworkManager) suspend an enabled kill switch.
    """
    cfg = config.load_config()
    enabled = killswitch.is_enabled()
    wanted = _killswitch_wanted(provider, enabled)
    ks_result = None
    ips: list[str] = []
    ifaces: list[str] = []
    hole_open = False
    if wanted:
        resolvers = killswitch.system_resolvers()
        if enabled and resolvers:
            # the current rules have no DNS hole: open it with the last known
            # addresses first, then resolve once with DNS working
            ips, ifaces = _killswitch_targets(provider, connection, cached_only=True)
            ks_result = _killswitch_apply(provider, ips, ifaces, resolvers)
            hole_open = ks_result is not None and ks_result.success
        fresh, ifaces = _killswitch_targets(provider, connection)
        if ks_result is None or not ks_result.success or set(fresh) != set(ips):
            ips = fresh
            ks_result = _killswitch_apply(provider, ips, ifaces, resolvers)
            hole_open = hole_open or bool(resolvers and ks_result and ks_result.success)
    elif enabled:
        ks_result = killswitch.suspend_for(provider.name)

    result = ActionResult(False, "")
    try:
        # one tunnel at a time: tear down anything else that is up before
        # connecting (two VPNs fight over the default route and traffic
        # splits unpredictably). Same-provider server switching is handled
        # inside the providers themselves (Happ/Keys stop their previous xray).
        others = [
            c
            for c in active_connections(providers=list(ALL_PROVIDERS))
            if not (c.provider == provider.name and c.name == connection.name)
        ]
        if others:
            down = _disconnect_all()  # already under SWITCH_LOCK
            if not down.success:
                return down
        tuns_before = _tun_interfaces()
        result = provider.connect(connection)
        if hole_open and result.success and provider.name == "OpenVPN":
            # `openvpn --daemon` returns before it resolves `remote`: keep the
            # DNS hole until its tun device exists (or the wait runs out)
            _wait_for_new_tun(tuns_before, OPENVPN_TUN_WAIT)
    finally:
        if hole_open:
            closed = _close_dns_hole(provider, ips, ifaces, result.success, cfg)
            if closed is not None:
                ks_result = closed
    if ks_result and not ks_result.success:
        notify("Killswitch — warning", ks_result.message)
    if result.success:
        if cfg.dns_autotest:
            request_dns_autotest()
        # don't re-probe: Happ reports success on happd's start ack, before
        # xray has created its TUN (and happd's process list may be the
        # cached pre-switch one) — a probe then sees nothing up and turned
        # IPv6 ON under a live tunnel. Success is proof enough.
        _apply_ipv6_guard(ipv6guard.disable())
    else:
        _sync_ipv6_guard()
    return result


SYS_NET = Path("/sys/class/net")
OPENVPN_TUN_WAIT = 20.0  # s the connect-time DNS hole stays open for OpenVPN


def _tun_interfaces() -> set[str]:
    try:
        return {p.name for p in SYS_NET.iterdir() if p.name.startswith("tun")}
    except OSError:
        return set()


def _wait_for_new_tun(before: set[str], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while not _tun_interfaces() - before:
        if time.monotonic() >= deadline:
            logutil.log(f"openvpn: no tun device after {timeout:g} s, closing the DNS hole anyway")
            return False
        time.sleep(0.5)
    return True


def _close_dns_hole(provider, ips: list[str], ifaces: list[str], connected: bool, cfg):
    """After a connect: the strict rules, without the connect-time DNS hole.
    A failed connect with Lockdown off drops the rules instead — unless
    something still looks up, then the strict rules all the same."""
    if not connected and not cfg.killswitch_lockdown and _release_killswitch_if_unlocked(cfg):
        return None
    result = _killswitch_apply(provider, ips, ifaces, [])
    if result is not None and not result.success:
        result.message = f"could not close the connect-time DNS exception: {result.message}"
    return result


def guarded_disconnect(provider, connection: VPNConnection) -> ActionResult:
    """_guarded_disconnect() under SWITCH_LOCK."""
    action = f"disconnecting {provider.name}: {connection.name}"
    try:
        with switch_lock(action):
            return _guarded_disconnect(provider, connection)
    except SwitchBusy as e:
        return _busy(e)
    except SwitchCancelled:
        return _cancelled(action)


def _guarded_disconnect(provider, connection: VPNConnection) -> ActionResult:
    """provider.disconnect() plus keeping the IPv6 guard in sync — every
    menu disconnect action should go through this, not provider.disconnect
    directly, so IPv6 gets restored as soon as nothing is left active."""
    result = provider.disconnect(connection)
    _sync_ipv6_guard()
    _release_killswitch_if_unlocked()
    return result


def _release_killswitch_if_unlocked(cfg=None) -> bool:
    """Lockdown off: the rules exist only while a VPN is up. Lockdown on
    (the default) keeps blocking until the user turns the kill switch off;
    the preference itself stays, so the next connect sets the rules again.
    True when the rules were dropped."""
    if (cfg or config.load_config()).killswitch_lockdown:
        return False
    # happd may still be stopping, and --status ticks cache its process
    # list for 3 s: a stale "Happ is up" kept the rules after a disconnect
    happ_provider._invalidate_procs_cache()
    if active_connections(providers=list(ALL_PROVIDERS)) or not killswitch.is_enabled():
        return False
    result = killswitch.disable()
    if not result.success:
        notify("Killswitch — warning", result.message)
    return result.success


def _sync_ipv6_guard() -> None:
    """IPv6 must be off while anything is tunneled (none of our providers
    route it, so it would otherwise leak straight past every tunnel) and
    back on once nothing is active."""
    if active_connections(providers=list(ALL_PROVIDERS)):
        _apply_ipv6_guard(ipv6guard.disable())
    else:
        _apply_ipv6_guard(ipv6guard.enable())


def _apply_ipv6_guard(guard: ActionResult) -> None:
    if not guard.success:
        notify("IPv6 guard — warning", guard.message)


def disconnect_all() -> ActionResult:
    """_disconnect_all() under SWITCH_LOCK."""
    try:
        with switch_lock("disconnecting everything"):
            result = _disconnect_all()
            _release_killswitch_if_unlocked()  # not in _disconnect_all: a connect reuses it
            return result
    except SwitchBusy as e:
        return _busy(e)
    except SwitchCancelled:
        return _cancelled("disconnecting everything")


def _disconnect_all() -> ActionResult:
    stopped, failed = [], []
    # act on everything, even providers hidden from the menu
    for provider in ALL_PROVIDERS:
        for conn in provider.connections():
            if not conn.active:
                continue
            result = provider.disconnect(conn)
            if result.success:
                stopped.append(f"{provider.name}: {conn.name}")
            elif not any(c.active for c in provider.connections()):
                # reported failure, but nothing is up anymore — e.g. one
                # Happ disconnect stops every happd process at once
                stopped.append(f"{provider.name}: {conn.name}")
            else:
                failed.append(f"{provider.name}: {conn.name}")
    _sync_ipv6_guard()
    if failed:
        return ActionResult(False, "Failed: " + ", ".join(failed))
    message = ", ".join(stopped) if stopped else "nothing was active"
    return ActionResult(True, f"Disconnected: {message}")


def manage_profiles(provider) -> ActionResult:
    """Second-level menu: pick a profile, then autostart/delete."""
    conns = provider.connections()
    if not conns:
        return ActionResult(False, f"No {provider.name} profiles found")

    profile_labels = [f"{c.name}{'  (connected)' if c.active else ''}" for c in conns]
    selected = menu_select(profile_labels, prompt=f"{provider.name} profile")
    if not selected:
        return ActionResult(True, "")
    conn = next((c for c in conns if selected.startswith(c.name)), None)
    if conn is None:
        return ActionResult(False, f"Unknown profile: {selected}")

    action_labels = ["Toggle autostart", "Delete config"]
    if conn.active:
        action_labels.insert(0, "Disconnect")
    selected = menu_select(action_labels, prompt=conn.name)
    if selected == "Toggle autostart":
        return provider.toggle_autostart(conn)
    if selected == "Delete config":
        return provider.delete_config(conn)
    if selected == "Disconnect":
        return guarded_disconnect(provider, conn)
    return ActionResult(True, "")


# ── Menu ──────────────────────────────────────────────────────────────────────
# Two levels, omarchy-style:
#   level 1 — provider choice (WireGuard / OpenVPN / Happ / ...) + global actions
#   level 2 — connections of the chosen provider + its import/manage actions


def _killswitch_all_targets(cached_only: bool = False) -> tuple[list[str], list[str]]:
    """'all' mode whitelist: IPv4 of every configured WireGuard/OpenVPN/
    Keys endpoint + the tunnel interface names to allow through.

    NetworkManager endpoints are not parsed (v1) — connecting one suspends
    the killswitch instead. One broken provider must not stop the others
    (pattern: _collect_ping_targets)."""
    targets: list[tuple[str, str, int]] = []
    ifaces: list[str] = []
    for provider in ALL_PROVIDERS:
        if provider.name == "NetworkManager":
            continue  # endpoints not parsed (v1) — connecting one suspends the killswitch
        try:
            pt = provider.ping_targets()
        except Exception as e:  # noqa: BLE001 — one broken provider must not stop the rest
            logutil.log(f"killswitch targets: {provider.name} skipped: {e!r}")
            continue
        targets += pt
        if provider.name in ("WireGuard", "AmneziaWG"):
            # wg-quick/awg-quick name the interface after the profile, and
            # the kernel caps interface names at 15 chars (IFNAMSIZ=16 with
            # NUL) — longer names can never exist as wg/awg interfaces (such
            # profiles are unused or driven by NetworkManager, which has
            # no such limit) and nft rejects the whole ruleset for them.
            ifaces += [n for n, _, _ in pt if len(n) <= 15]
            for n, _, _ in pt:
                if len(n) > 15:
                    logutil.log(f"killswitch: iface name too long, skipped: {n}")
        elif provider.name == "OpenVPN":
            if pt:
                ifaces.append("tun*")  # OpenVPN tunnel interfaces
        elif isinstance(provider, KeysProvider) and pt:
            ifaces.append(provider.tunnel_iface)
    targets += happmeta.subscription_targets()  # refreshes must survive the killswitch
    return killswitch.resolve_endpoint_ips(targets, cached_only=cached_only), sorted(set(ifaces))


def _killswitch_toggle(on: bool) -> ActionResult:
    if not on:
        return killswitch.set_mode(False)
    if not config.load_config().killswitch_lockdown and not active_connections(
        providers=list(ALL_PROVIDERS)
    ):
        return killswitch.set_mode(True, apply=False)  # nothing to protect yet
    ips, ifaces = _killswitch_all_targets()
    return killswitch.set_mode(True, extra_ips=ips, ifaces=ifaces)


KILLSWITCH_ICON = settings_tui.KILLSWITCH_ICON


def _killswitch_item() -> tuple[str, Callable]:
    if killswitch.is_enabled() or killswitch.mode() in ("happ", "all"):
        return (
            f"{KILLSWITCH_ICON} Killswitch: ON — click to disable",
            lambda: _killswitch_toggle(False),
        )
    return (
        f"{KILLSWITCH_ICON} Killswitch: OFF — click to enable (all)",
        lambda: _killswitch_toggle(True),
    )


def _dns_leak_server_row(
    server: dict, ip_country: str = "", ip_asn: int | None = None
) -> tuple[str, Callable]:
    """One row per detected resolver — the wider menu card (see
    MENU_WIDTH) is the actual fix for these getting truncated; no need to
    collapse the list to make it fit. 'Leaked' when dnsleak.server_tags()
    finds the resolver is neither the VPN's nor a public one (ASN) or sits in
    another country than the exit IP (GEO) — wherever that country is."""
    country = (server.get("country") or "").upper()
    flag = ipinfo.flag_emoji(country)
    org = server.get("org") or server.get("asn") or ""
    label = f"{flag} {server.get('ip') or '?'}".strip()
    if org:
        label += f" · {org}"
    if dnsleak.server_tags(server, ip_country, ip_asn):
        label += "  Leaked"
    return (label, lambda: ActionResult(True, ""))


_FLAG = re.compile("[\U0001f1e6-\U0001f1ff]{2}")  # a pair of regional indicators
# 🇪🇺 is not a country — 13 real servers carry it and exit in a member state
# fmt: off
EU_MEMBERS = frozenset(
    {
        "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES",
        "FI", "FR", "GR", "HR", "HU", "IE", "IT", "LT", "LU",
        "LV", "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK",
    }
)
# fmt: on


def _exit_fits(expected: str, ip_country: str) -> bool:
    return expected == ip_country or (expected == "EU" and ip_country in EU_MEMBERS)


def _name_flag_country(name: str) -> str | None:
    """Country code of the first flag emoji in a server name, if any."""
    m = _FLAG.search(name)
    if not m:
        return None
    return "".join(chr(ord("A") + ord(c) - 0x1F1E6) for c in m.group())


def _dns_leak_exit_row(
    ip_country: str, active: list[VPNConnection], exit_ip: str | None = None
) -> str:
    """Does the public IP bash.ws saw fit the active connection? Compared by
    country. The expected exit country is the flag in the server's name —
    providers label servers by where traffic exits, and whitelist-bypass
    bridges ("🇩🇪 Германия+", DE+-RU-* members) enter in RU and exit in DE by
    design. Without a flag, the reputation sweep's (entry IP) country. The
    exit IP legitimately differs from the endpoint (bridges, CDN-fronted
    xray), but a different country than expected is a red flag — unless a
    second geo DB (ipwho.is, ipinfo.country_of_ip) puts the same exit IP in
    the expected country: leased blocks geolocate inconsistently."""
    if not active:
        return "No VPN active — this is your real IP"
    known = [
        (c.name, cc)
        for c in active
        if (cc := _name_flag_country(c.name) or reputation.country_of(c.name))
    ]
    if not known:
        return f"VPN: {active[0].name}"
    for name, cc in known:
        if _exit_fits(cc, ip_country):
            return f"Exit matches {name} {ipinfo.flag_emoji(cc)}"
    second = ipinfo.country_of_ip(exit_ip) if exit_ip else None
    if second:
        for name, cc in known:
            if _exit_fits(cc, second):
                flag, theirs = ipinfo.flag_emoji(cc), ipinfo.flag_emoji(ip_country)
                return f"Exit matches {name} {flag} · bash.ws: {theirs}"
    name, cc = known[0]
    return f"Leaked: exit ≠ {name} {ipinfo.flag_emoji(cc)}"


def _dns_leak_ipv6_row(vpn_active: bool) -> str:
    if ipv6guard.is_disabled():
        return "IPv6: disabled"
    return "Leaked: IPv6 enabled — bypasses the tunnel" if vpn_active else "IPv6: enabled"


def _dns_leak_verdict_row(result: dict) -> str | None:
    """Own verdict over every resolver, shown next to bash.ws's. None when
    the exit IP's country and ASN are both unknown — server_tags() would
    then flag nobody, and an all-clear built on no data would be a lie."""
    servers = result["dns_servers"]
    ip_country, ip_asn = result["ip_country"], result.get("ip_asn")
    if not servers or not (ip_country or ip_asn):
        return None
    flagged = sum(1 for s in servers if dnsleak.server_tags(s, ip_country, ip_asn))
    if flagged:
        return f"Leaked: {flagged}/{len(servers)} DNS outside VPN/public resolvers"
    return "DNS via VPN or public resolvers"


def _failure_hint(reason: str) -> str:
    """Why a network tool most likely failed, beyond its raw error.

    No VPN + killswitch on: every packet is dropped by design (killswitch_mode
    "all"/"happ" keeps it on after a disconnect) — the raw error is just a
    timeout. Through a tunnel, a timeout is rarely "no network": usually the
    exit is slow or blocks the target (seen: TLS handshakes of 6-8 s on one
    exit; on two others even the exit-IP check timed out at the same time)."""
    if not active_connections() and killswitch.is_enabled():
        return " — the killswitch blocks all traffic while no VPN is connected"
    if "timed out" in reason.lower():
        return " — the VPN exit may be slow or blocking it; try another server"
    return ""


DNS_VERDICT_CACHE = Path.home() / ".cache/vpn-manager/dns-leak.json"
DNS_VERDICT_MAX_AGE = 24 * 3600  # a verdict outlives neither a day nor a server switch


def _save_dns_verdict(active: list[VPNConnection], verdict: str | None) -> None:
    """The last test's resolver verdict, for the panel's DNS badge — keyed
    to the connection it ran under; None (no data to judge) is kept too."""
    record = {
        "at": time.time(),
        "connection": active[0].name if active else None,
        "leaked": None if verdict is None else verdict.startswith("Leaked"),
        "summary": verdict,
    }
    with contextlib.suppress(OSError):
        fsutil.write_json_atomic(DNS_VERDICT_CACHE, record)


def _read_dns_verdict(connection: str) -> dict | None:
    try:
        record = json.loads(DNS_VERDICT_CACHE.read_text())
    except OSError, ValueError:
        return None
    if not isinstance(record, dict) or record.get("connection") != connection:
        return None
    if time.time() - record.get("at", 0) > DNS_VERDICT_MAX_AGE:
        return None
    return record


DNS_AUTOTEST_WAIT = 20  # s for the tunnel to show up (Happ acks before xray's TUN exists)
DNS_AUTOTEST_SETTLE = 3  # s more for routes and DNS to settle


def request_dns_autotest() -> None:
    """Fire-and-forget --dns-autotest after a connect (config dns_autotest)."""
    subprocess.Popen(
        [sys.executable, str(Path(__file__)), "--dns-autotest"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def run_dns_autotest() -> None:
    """The DNS leak test without a menu or progress bubbles: wait for the
    tunnel, test, store the verdict for the panel's DNS badge (which is
    what turns "Unverified" into "Protected"). Only a leak is announced."""
    deadline = time.monotonic() + DNS_AUTOTEST_WAIT
    active = active_connections()
    while not active and time.monotonic() < deadline:
        time.sleep(1)
        active = active_connections()
    if not active:
        logutil.log("dns autotest: no tunnel came up, skipped")
        return
    time.sleep(DNS_AUTOTEST_SETTLE)
    try:
        result = dnsleak.run()
    except dnsleak.LeakTestError as e:
        logutil.log(f"dns autotest: {e}")
        return
    verdict = _dns_leak_verdict_row(result)
    _save_dns_verdict(active, verdict)
    logutil.log(f"dns autotest: {active[0].name}: {verdict}")
    if verdict and verdict.startswith("Leaked"):
        notify("DNS leak detected", f"{active[0].label}\n{verdict}", urgent=True)
    refresh_bar()


def _cancel_check(signum, frame) -> None:
    raise CheckCancelled


def dns_leak_test_menu() -> ActionResult:
    """DNS leak test — same backend (bash.ws) as dnsleaktest.com. Runs
    synchronously (a few seconds of DNS probes) and shows the result as a
    submenu rather than a single notification, so a long DNS-server list
    stays readable instead of getting truncated in a notify-send bubble."""
    progress = notifyutil.Progress("DNS Leak Test", steps=len(dnsleak.STEPS))
    # a switch SIGTERMs a running test (_abort_checks): it would test the
    # server being left — close the bubble instead of leaving it spinning
    previous = signal.signal(signal.SIGTERM, _cancel_check)
    try:
        result = dnsleak.run(on_step=lambda n, label: progress.step(n, f"{label}…"))
    except dnsleak.LeakTestError as e:
        progress.fail(f"Test {e}{_failure_hint(e.reason)}")
        return ActionResult(False, "")  # already notified, with the reason
    except CheckCancelled:
        logutil.log("DNS Leak Test cancelled: the connection changed")
        progress.done("Cancelled — the connection changed")
        return ActionResult(False, "")
    finally:
        signal.signal(signal.SIGTERM, previous)
    progress.done("Done")

    active = active_connections()
    ip_country, ip_asn = result["ip_country"], result.get("ip_asn")
    items: list[tuple[str, Callable]] = []
    if result["ip"]:
        flag = ipinfo.flag_emoji(ip_country)
        items.append((f"IP: {result['ip']} {flag}".strip(), lambda: ActionResult(True, "")))
    exit_row = _dns_leak_exit_row(ip_country, active, result["ip"])
    items.append((exit_row, lambda: ActionResult(True, "")))
    items.append((_dns_leak_ipv6_row(bool(active)), lambda: ActionResult(True, "")))
    if result["dns_servers"]:
        items.extend(_dns_leak_server_row(s, ip_country, ip_asn) for s in result["dns_servers"])
    else:
        items.append(("No DNS servers found", lambda: ActionResult(True, "")))
    verdict = _dns_leak_verdict_row(result)
    _save_dns_verdict(active, verdict)
    if verdict:
        items.append((verdict, lambda: ActionResult(True, "")))
    if result["conclusion"]:
        items.append((f"bash.ws: {result['conclusion']}", lambda: ActionResult(True, "")))
    items.append((BACK_LABEL, tools_menu))
    run_items(_unique_labels(items), prompt="DNS Leak Test")
    return ActionResult(True, "")


def _ip_info_flag_row(label: str, value: bool | None) -> tuple[str, Callable]:
    text = "Yes" if value else "No"
    return (f"{label}: {text}", lambda: ActionResult(True, ""))


def ip_info_menu() -> ActionResult:
    """Multi-source exit-IP report — one row group per enabled ipsources
    source (free ones on by default; keyed ones once their API key is
    set). A single ad-hoc lookup for the current public IP, not the
    background reputation sweep."""
    progress = notifyutil.Progress("IP Info", steps=2)
    reached: list[int] = []

    def on_step(n: int, label: str) -> None:
        reached.append(n)
        progress.step(n, f"{label}…")

    findings = reputation.lookup_self(include_keyed=True, on_step=on_step)
    if not findings:
        if 2 not in reached:
            reason = "could not detect your public IP (ipwho.is, ifconfig.me)"
        else:
            reason = f"no IP source answered within {reputation.LOOKUP_TIMEOUT:.0f} s"
        progress.fail(f"Failed: {reason}{_failure_hint(reason)}")
        return ActionResult(False, "")  # already notified, with the reason
    progress.done("Done")

    items: list[tuple[str, Callable]] = [(f"IP: {findings[0].ip}", lambda: ActionResult(True, ""))]
    for finding in findings:
        parts = [p for p in (finding.country_name, finding.org) if p]
        if finding.abuse_score is not None:
            parts.append(f"abuse {finding.abuse_score}/100")
        label = f"{finding.source}: {' · '.join(parts)}" if parts else finding.source
        items.append((label, lambda: ActionResult(True, "")))
    items.append(_ip_info_flag_row("🏢 Datacenter/Hosting", any(f.hosting for f in findings)))
    items.append(_ip_info_flag_row("🕵️ Proxy/VPN detected", any(f.proxy for f in findings)))
    items.append(_ip_info_flag_row("📱 Mobile network", any(f.mobile for f in findings)))
    items.append((BACK_LABEL, tools_menu))
    run_items(_unique_labels(items), prompt="IP Info")
    return ActionResult(True, "")


SPEED_TEST_TITLE = "Speed Test"  # menu prompt + progress notification title
SPEED_TEST_ALL_LABEL = "🌍 All services"
SPEED_TEST_CUSTOM_LABEL = "✏️ Custom URL…"
SPEED_TEST_MAX_URLS = 5  # remembered custom URLs, newest first
# per service in "All services" — run one after another (in parallel they'd
# split the same uplink and each report a fraction of it), so this keeps
# the whole sweep around half a minute
SPEED_TEST_ALL_DURATION = 5.0


def speed_test_menu() -> ActionResult:
    """Pick a service (or all of them), then measure download throughput
    through whatever the current route is (tunnel or, with no VPN up, the
    plain uplink). Results open in their own menu, like the DNS
    leak test — a multi-service comparison doesn't fit a notify bubble."""
    # public presets, then custom URLs remembered in config.json
    # (`speed_test_urls` — e.g. a test stand's own file server)
    targets = [("🌐", s.name, s.url) for s in speedtest.SERVICES]
    preset_urls = {s.url for s in speedtest.SERVICES}
    targets += [
        ("🔗", url, url)
        for url in config.load_config().speed_test_urls
        if url not in preset_urls  # its preset row already covers it
    ]
    every = [(name, url) for _icon, name, url in targets]
    items: list[tuple[str, Callable]] = [
        (SPEED_TEST_ALL_LABEL, lambda: _run_speed_tests(every, SPEED_TEST_ALL_DURATION))
    ]
    items += [
        (f"{icon} {name}", lambda t=(name, url): _run_speed_tests([t]))
        for icon, name, url in targets
    ]
    items.append((SPEED_TEST_CUSTOM_LABEL, _speed_test_custom_url))
    items.append((BACK_LABEL, tools_menu))
    run_items(_unique_labels(items), prompt=SPEED_TEST_TITLE)
    return ActionResult(True, "")


def _speed_test_custom_url() -> ActionResult:
    url = menu_input("Speed test URL (http/https, large file)")
    if not url:
        return ActionResult(False, "No URL entered")
    if not speedtest.is_valid_url(url):
        return ActionResult(False, f"Not an http(s) URL: {url}")
    cfg = config.load_config()
    cfg.speed_test_urls = [url, *(u for u in cfg.speed_test_urls if u != url)][:SPEED_TEST_MAX_URLS]
    config.save_config(cfg)
    return _run_speed_tests([(url, url)])


def _run_speed_tests(
    targets: list[tuple[str, str]], duration: float = speedtest.DURATION
) -> ActionResult:
    """Measure each target in turn (progress in one notification replaced
    step by step — the menu can't update while a test runs), then
    show every result in one window."""
    steps = len(targets) if len(targets) > 1 else None
    progress = notifyutil.Progress(SPEED_TEST_TITLE, steps=steps)
    results = []
    for i, (name, url) in enumerate(targets, 1):
        progress.step(i, f"{name}: measuring for ~{duration:.0f} s…")
        results.append((name, speedtest.measure(url, duration)))

    noop = lambda: ActionResult(True, "")  # noqa: E731 — info rows do nothing
    active = active_connections()
    items: list[tuple[str, Callable]] = [
        (_speed_test_route_row(active), noop),
        *((_speed_test_result_row(name, m), noop) for name, m in results),
    ]
    ok = [(name, m.mbps) for name, m in results if m.mbps is not None]
    if ok:
        progress.done(f"Done — {len(ok)}/{len(results)} measured")
    else:
        first = next(m.error for _name, m in results if m.error)
        progress.fail(f"All {len(results)} failed — {first}{_failure_hint(first)}")
    if len(results) > 1 and ok:
        best = max(ok, key=lambda r: r[1])
        items.append((f"🏆 Fastest: {best[0]} ({best[1]:.1f} Mbit/s)", noop))
    if not ok and killswitch.is_enabled() and not active:
        items.append(("⚠ Killswitch is on and no VPN is active — traffic is blocked", noop))
    items.append(("🔁 Run again", lambda: _run_speed_tests(targets, duration)))
    items.append((BACK_LABEL, speed_test_menu))
    run_items(_unique_labels(items), prompt=SPEED_TEST_TITLE)
    return ActionResult(True, "")


def _speed_test_route_row(active: list[VPNConnection]) -> str:
    if not active:
        return "Route: direct (no VPN)"
    return "Route: " + ", ".join(c.label for c in active)


def _speed_test_result_row(name: str, m: speedtest.Measurement) -> str:
    if m.mbps is not None:
        return f"{name}: ⬇ {m.mbps:.1f} Mbit/s"
    return f"{name}: ✗ {m.error}"


def refresh_all_menu() -> ActionResult:
    """Force a ping sweep (every provider) + Happ subscription sync now,
    bypassing PING_MAX_AGE/SUB_MAX_AGE — request_ping_update()/
    request_subscription_update() are staleness-gated and would otherwise
    no-op if the last sweep was recent. Reputation is deliberately
    excluded (its own daily cadence + IPAPI_PACE already make it a
    multi-minute background job; forcing it from a menu click isn't
    "refresh now", it's "wait a while", which belongs to its own timer)."""
    subprocess.Popen(
        [sys.executable, str(Path(__file__)), "--update-ping"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    subprocess.Popen(
        [sys.executable, str(Path(__file__)), "--update-subs-force"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return ActionResult(True, "Refresh started in the background")


CACHE_DIR = Path.home() / ".cache/vpn-manager"


def clear_caches_menu() -> ActionResult:
    """Every cache this project writes lives under CACHE_DIR (happmeta's
    PING_CACHE/PROVIDERS_CACHE, reputation.CACHE, ipinfo.CACHE_PATH,
    providers/base.py's RATE_CACHE) — safe to delete on demand, every reader
    already tolerates a missing file. subscription-*.json is kept: it is
    server data, refreshed in place by the subscription sweep.
    ~/.config/happ-capture/ is NOT touched — that's captured server data,
    not a cache."""
    removed = 0
    if CACHE_DIR.is_dir():
        for f in CACHE_DIR.glob("*.json"):
            if f.name.startswith("subscription-"):
                # the only offline copy of a subscription's servers: deleting
                # it empties the Happ menu until a refetch succeeds, which a
                # killswitch or a dead network can block indefinitely
                continue
            with contextlib.suppress(OSError):
                f.unlink()
                removed += 1
    return ActionResult(True, f"Cache cleared ({removed} files) — rebuilt automatically")


class Prompter(ABC):
    @abstractmethod
    def confirm(self, question: str, default: bool) -> bool: ...

    @abstractmethod
    def text(self, question: str) -> str: ...


class TerminalPrompter(Prompter):
    def confirm(self, question: str, default: bool) -> bool:
        suffix = "[Y/n]" if default else "[y/N]"
        try:
            answer = input(f"{question} {suffix} ").strip().lower()
        except EOFError, KeyboardInterrupt:
            return default
        return default if not answer else answer in ("y", "yes")

    def text(self, question: str) -> str:
        try:
            return getpass.getpass(f"{question}: ").strip()
        except EOFError, KeyboardInterrupt:
            return ""


def run_configure_wizard(prompter: Prompter) -> bool:
    """The question-by-question walk behind --configure (install.sh's last
    step, in a terminal). The in-menu ⚙️ Settings is a list instead
    (settings_tui.py). Never touches an existing config.json unless the
    user opts in via the first confirm. Returns False when the user
    declines reconfigure on an existing file; True after save."""
    if config.CONFIG_PATH.exists():
        if not prompter.confirm("Config already exists. Reconfigure?", False):
            return False
        cfg = config.load_config()
    else:
        cfg = config.Config()

    for provider in ALL_PROVIDERS:
        visible = prompter.confirm(f"Show {provider.name}?", cfg.provider_visible(provider.name))
        cfg.providers[provider.name.lower()] = visible

    for key, label, _fn in [*TOOLS, ("killswitch", "Killswitch", None)]:
        visible = prompter.confirm(f"Show tool “{label}”?", cfg.tool_visible(key))
        cfg.tools_visible[key] = visible

    for source in ipsources.ALL_SOURCES:
        if source.needs_api_key:
            answer = prompter.text(f"{source.name} API key (Enter — keep current / skip)")
            if answer:
                cfg.ip_sources.setdefault(source.key, {})["api_key"] = answer
        else:
            enabled = prompter.confirm(f"Use {source.name}?", source.is_enabled())
            cfg.ip_sources.setdefault(source.key, {})["enabled"] = enabled

    # no: route xray's DNS the way the subscription says — some pin their
    # resolvers "direct", which sends every lookup out the real connection
    tunnel = prompter.confirm(
        "Force all Happ DNS through the VPN tunnel (ignore subscription DNS routing)?",
        cfg.dns_mode == "tunnel",
    )
    cfg.dns_mode = "tunnel" if tunnel else "subscription"

    config.save_config(cfg)
    return True


# ── ⚙ Settings: a list in a small floating terminal (settings_tui.py) — omarchy.menu
# can't change a row in place or keep the cursor where it was.

SETTINGS_WINDOW_CLASS = "TUI.float"  # omarchy floats + centres this class (875×600)
SETTINGS_WINDOW_TITLE = "VPN Settings"


def _settings_tool_keys() -> list[tuple[str, str]]:
    # ⚙ Settings can't hide itself from there: that would lock the user out
    # of the window (--configure or config.json still can)
    return [(key, label) for key, label, _fn in TOOLS if key != "settings"] + [
        ("killswitch", f"{KILLSWITCH_ICON} Killswitch")
    ]


def settings_menu() -> ActionResult:
    terminal = [
        "xdg-terminal-exec",
        f"--app-id={SETTINGS_WINDOW_CLASS}",
        f"--title={SETTINGS_WINDOW_TITLE}",
        "-e",
        sys.executable,
        str(Path(__file__)),
        "--settings",
    ]
    if shutil.which("uwsm-app"):  # omarchy launches apps as their own systemd scope
        terminal = ["uwsm-app", "--", *terminal]
    # omarchy's launch-or-focus (what its TUIs open through): a second click
    # focuses the open window instead of stacking another one. It matches the
    # title too, and eval's the command — hence shlex.join.
    if shutil.which("omarchy-launch-or-focus"):
        cmd = ["omarchy-launch-or-focus", SETTINGS_WINDOW_TITLE, shlex.join(terminal)]
    else:
        cmd = terminal
    try:
        subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True
        )
    except OSError:
        return ActionResult(
            False, "No terminal launcher (xdg-terminal-exec) — run vpn_manager.py --settings"
        )
    return ActionResult(True, "")


def run_settings_window() -> None:
    """--settings, inside the terminal settings_menu() opened."""
    if settings_tui.main([p.name for p in ALL_PROVIDERS], _settings_tool_keys()):
        notify("VPN", "Settings saved")
        refresh_bar()


# single source of truth for both tools_menu()'s rows and the configure
# wizard's questions (key, label, action) — killswitch is handled
# separately in both places since its row reflects live on/off state
# (_killswitch_item()), not a fixed action function.
TOOLS = [
    ("dns_leak_test", "🔍 DNS Leak Test", dns_leak_test_menu),
    ("ip_info", "ℹ️ IP Info", ip_info_menu),
    ("speed_test", "⚡ Speed Test", speed_test_menu),
    ("refresh_all", "🔄 Refresh All", refresh_all_menu),
    ("clear_caches", "🗑️ Clear Caches", clear_caches_menu),
    ("settings", "⚙️ Settings", settings_menu),
]


def tools_menu() -> ActionResult:
    cfg = config.load_config()
    items = [(label, fn) for key, label, fn in TOOLS if cfg.tool_visible(key)]
    if cfg.tool_visible("killswitch") and not _killswitch_unsupported(active_connections()):
        items.append(_killswitch_item())
    items.append((BACK_LABEL, back_to_main))
    run_items(_unique_labels(items), prompt="Tools")
    return ActionResult(True, "")


def provider_actions(provider) -> list[tuple[str, Callable]]:
    """Import / manage entries for providers that support them."""
    if provider.name in ("WireGuard", "AmneziaWG"):
        return [
            (
                f"  Import {provider.name} config...",
                lambda: import_config_file(provider, provider.name),
            ),
            (
                f"  Manage {provider.name} profiles...",
                lambda: manage_profiles(provider),
            ),
        ]
    if provider.name == "OpenVPN":
        return [("  Import OpenVPN config...", lambda: import_config_file(provider, "OpenVPN"))]
    if provider.name in ("VLESS", "Shadowsocks"):
        return [("  Import key...", lambda: import_config_file(provider, provider.name))]
    if provider.name == "NetworkManager":
        return [
            (
                "  Import VPN config into NetworkManager...",
                lambda: import_config_file(provider, "NetworkManager"),
            ),
            ("  Manage NetworkManager profiles...", lambda: manage_profiles(provider)),
        ]
    return []


def menu_loop() -> ActionResult:
    """Level 1: the active connection with metrics, providers to pick from,
    quick disconnect, and the killswitch toggle — always the last row."""
    items: list[tuple[str, Callable]] = []

    all_active = active_connections(providers=list(ALL_PROVIDERS))
    if all_active:
        items.extend(_current_connection_items(all_active[0]))
    else:
        ip_row = _no_vpn_ip_item()
        if ip_row:
            items.append(ip_row)

    # every provider not hidden in ⚙ Settings, empty ones too: their submenu
    # is where the Import/Manage rows live (Happ's explains missing headers)
    for provider in visible_providers():
        conns = provider.connections()
        active = sum(1 for c in conns if c.active)
        label = f"{provider.name}  ({active}/{len(conns)})"
        items.append((label, lambda p=provider: provider_menu(p)))

    if all_active:
        if len(all_active) == 1:
            first = all_active[0]
            items.append((f"Disconnect: {first.label}", disconnect_all))
        else:
            items.append((f"Disconnect ALL  ({len(all_active)})", disconnect_all))

    items.append(("🛠️ Tools", tools_menu))
    return run_items(items, prompt="VPN")


def _current_connection_items(conn: VPNConnection) -> list[tuple[str, Callable]]:
    """First menu rows: what is connected + live metrics. Row 1 reconnects
    the server; row 2 (metrics, indented) shows the full detail card.
    dmenu rows are single-line, so the metrics get their own row instead
    of being truncated by the menu width."""
    cfg = config.load_config()
    metrics = []
    rate = iface_rate(conn.interface)
    if rate:
        metrics.append(rate)
    if cfg.exit_ip_enabled:
        exit_line = ipinfo.status_line(conn.name, cfg.exit_ip_max_age)
        if exit_line:
            metrics.append(exit_line.removeprefix("Exit: "))
        else:
            request_ip_update(conn.name)
    rows = [(f"↻ {conn.label}", lambda: _reconnect(conn))]
    if metrics:
        rows.append((("     " + " · ".join(metrics)), lambda: _details(conn, cfg)))
    return rows


def _details(conn: VPNConnection, cfg) -> ActionResult:
    lines = [conn.label]
    if conn.interface:
        live = iface_rate(conn.interface)
        totals = iface_traffic(conn.interface)
        if live:
            lines.append(live)
        if totals:
            lines.append(totals)
    exit_line = ipinfo.status_line(conn.name, cfg.exit_ip_max_age)
    if exit_line:
        lines.append(exit_line)
    notify("VPN — connection", "\n".join(lines))
    return ActionResult(True, "")


def _reconnect(conn: VPNConnection) -> ActionResult:
    provider = next((p for p in ALL_PROVIDERS if p.name == conn.provider), None)
    if provider is None:
        return ActionResult(False, f"Unknown provider: {conn.provider}")
    down = guarded_disconnect(provider, conn)
    if not down.success:
        return down
    return guarded_connect(provider, conn)


def _no_vpn_ip_item() -> tuple[str, Callable] | None:
    """Not connected: the first row shows the real public IP (cache-first —
    the --status tick is not running to refresh it, so trigger a fetch when
    stale). Click re-fetches and shows the full line."""
    cfg = config.load_config()
    if not cfg.exit_ip_enabled:
        return None
    exit_line = ipinfo.status_line(NO_VPN, cfg.exit_ip_max_age)
    if exit_line is None:
        request_ip_update(NO_VPN)
        label = "● No VPN"
    else:
        label = f"● No VPN · {exit_line.removeprefix('Exit: ')}"

    def _refresh() -> ActionResult:
        line = ipinfo.status_line(NO_VPN, cfg.exit_ip_max_age)
        if line is None:
            request_ip_update(NO_VPN)
            return ActionResult(True, "IP refresh started — reopen the menu to see it")
        notify("VPN", line)
        return ActionResult(True, "")

    return (label, _refresh)


def provider_menu(provider) -> ActionResult:
    """Level 2: connections of one provider, plus its actions."""
    if provider.name == "Happ":
        return happ_menu(provider)

    happmeta.request_ping_update()
    reputation.request_update()
    items: list[tuple[str, Callable]] = []
    for conn in provider.connections():
        info = happmeta.ping_mark(conn.name)
        suffix = f"    {info}" if info else ""
        if conn.active:
            items.append(
                (f"Disconnect {conn.name}{suffix}", lambda c=conn: guarded_disconnect(provider, c))
            )
        else:
            label = f"{conn.name}{suffix}"
            items.append((label, lambda c=conn: guarded_connect(provider, c)))
    items.extend(provider_actions(provider))
    items.append((BACK_LABEL, back_to_main))
    run_items(_unique_labels(items), prompt=provider.name)
    # The submenu already notified/refreshed; stay silent for the parent level.
    return ActionResult(True, "")


def back_to_main() -> ActionResult:
    menu_loop()
    return ActionResult(True, "")


# ── Happ: providers -> servers (with ping/protocol info) ─────────────────────


def happ_server_groups(provider) -> tuple[list[dict], dict[str, list[dict]]]:
    """(all servers, subscription name -> its rows) with the active server
    marked — shared by the Happ menu and the panel's server list."""
    servers = happmeta.all_servers(allow_fetch=False)
    active_conns = [c for c in provider.connections() if c.active]

    # Exact match, or the unique substring match (GUI names can lack the
    # emoji prefix); ambiguous prefixes mark nothing. Matched by
    # (subscription, name) — the same name in another subscription is a
    # different server and must not light up too.
    matched = {
        (m["provider_id"], m["name"])
        for c in active_conns
        if (m := happmeta.match_server(c.name, servers, c.subscription_id))
    }
    groups: dict[str, list] = {}
    for server in servers:
        is_active = (server["provider_id"], server["name"]) in matched
        groups.setdefault(server["provider_name"], []).append(
            {
                "name": server["name"],
                "active": is_active,
                "provider_id": server["provider_id"],
                "protocol": happmeta.protocol_label(server["config"]),
            }
        )
    return servers, groups


def happ_menu(provider) -> ActionResult:
    """Happ level 2: subscription providers, each leading to its servers."""
    happmeta.request_subscription_update()
    happmeta.request_ping_update()
    reputation.request_update()
    servers, groups = happ_server_groups(provider)

    items: list[tuple[str, Callable]] = []
    for pname, group in groups.items():
        active = sum(1 for g in group if g["active"])
        summary = happmeta.provider_ping_summary([g["name"] for g in group])
        suffixes = []
        if active:
            suffixes.append(f"{active}/{len(group)}")
        if summary:
            suffixes.append(summary)
        label = pname
        if suffixes:
            label += "  (" + " · ".join(suffixes) + ")"
        items.append((label, lambda p=pname, g=group: happ_provider_menu(provider, p, g)))
    rejected = _happ_rejected_rows(set(groups))
    items.extend(rejected)
    if not servers and not rejected and not happmeta.has_headers():
        items.append((HAPP_NO_HEADERS_LABEL, _happ_no_headers))
    items.append(("  Refresh subscriptions", _refresh_subscriptions))
    items.append((BACK_LABEL, back_to_main))
    run_items(items, prompt="Happ")
    # the submenu already notified; returning None crashed the caller's result.success
    return ActionResult(True, "")


HAPP_NO_HEADERS_LABEL = "⚠️ No servers: provider may need captured Happ headers"


# ── Panel: server list + connect/disconnect ───────────────────────────────────


def _server_row(entry: dict) -> dict:
    """One server for the panel. A stale ping (no sweep under the killswitch)
    keeps its last value with a "~" and stale=True — the panel dims it."""
    state, ms = happmeta.ping_status(entry["name"])
    if state == "none":
        ping = ""  # never swept: say nothing rather than guess
    elif ms is None:
        ping = "timeout"
    else:
        ping = f"{ms:.0f} ms"
    if ms is not None and state == "stale":
        ping = "~" + ping  # an old number; an old timeout is just dimmed
    return {
        "name": entry["name"],
        "active": bool(entry["active"]),
        "protocol": entry.get("protocol", ""),
        "ping": ping,
        "ping_ms": ms if state != "none" else None,
        "stale": state == "stale",
        # the flag's country code, so the filter finds "Польша" by "pl"
        "country": (_name_flag_country(entry["name"]) or "").lower(),
    }


def _server_group(group_id: str, provider: str, title: str, entries: list[dict], sub_id=None):
    rows = [_server_row(e) for e in entries]
    reachable = [r["ping_ms"] for r in rows if r["ping_ms"] is not None]
    summary = ""
    if reachable:
        median = sorted(reachable)[len(reachable) // 2]
        stale = "~" if any(r["stale"] for r in rows if r["ping_ms"] is not None) else ""
        summary = f"✓ {len(reachable)}/{len(rows)} · {stale}{median:.0f} ms"
    return {
        "id": group_id,
        "provider": provider,
        "title": title,
        "subscription_id": sub_id or "",
        "summary": summary,
        "active": any(r["active"] for r in rows),
        "servers": rows,
    }


def server_list() -> dict:
    """--servers: the panel's list — every visible provider's connections,
    Happ split per subscription — with ping and protocol. Cache reads only
    (it runs when the panel opens); stale subscriptions and pings refresh
    in the background like the menu's."""
    happmeta.request_subscription_update()
    happmeta.request_ping_update()
    groups = []
    for provider in visible_providers():
        if provider.name == "Happ":
            _servers, happ_groups = happ_server_groups(provider)
            for pname, entries in happ_groups.items():
                sub_id = entries[0].get("provider_id") or ""
                groups.append(
                    _server_group(f"happ:{sub_id}:{pname}", "Happ", pname, entries, sub_id)
                )
            continue
        try:
            conns = provider.connections()
        except Exception as e:  # noqa: BLE001 — one broken provider must not empty the list
            logutil.log(f"server list: {provider.name} skipped: {e!r}")
            continue
        if conns:
            entries = [{"name": c.name, "active": c.active} for c in conns]
            groups.append(_server_group(provider.name, provider.name, provider.name, entries))
    return {"groups": groups}


def _provider_named(name: str):
    return next((p for p in ALL_PROVIDERS if p.name == name), None)


def panel_connect(provider_name: str, name: str, sub_id: str | None = None) -> ActionResult:
    """--connect from the panel: the same guarded_connect() as the menu
    (killswitch, IPv6 guard, one tunnel at a time, DNS autotest)."""
    provider = _provider_named(provider_name)
    if provider is None:
        return ActionResult(False, f"Unknown provider: {provider_name}")
    if provider.name == "Happ":
        sub_name = happmeta.providers().get(sub_id or "", {}).get("name") if sub_id else None
        conn = VPNConnection(
            name=name,
            provider="Happ",
            active=False,
            subscription_id=sub_id or None,
            subscription_name=sub_name,
        )
    else:
        found = next((c for c in provider.connections() if c.name == name), None)
        if found is None:
            return ActionResult(False, f"{provider_name}: {name} not found")
        conn = found
    return guarded_connect(provider, conn)


def panel_disconnect(provider_name: str, name: str) -> ActionResult:
    """--disconnect from the panel. Happ's active connection name can differ
    from the subscription's server name (GUI names lack the emoji), so for
    Happ any active connection of it is the one."""
    provider = _provider_named(provider_name)
    if provider is None:
        return ActionResult(False, f"Unknown provider: {provider_name}")
    active = [c for c in provider.connections() if c.active]
    conn = next((c for c in active if c.name == name), None)
    if conn is None and provider.name == "Happ" and active:
        conn = active[0]
    if conn is None:
        return ActionResult(False, f"{provider_name}: {name} is not connected")
    return guarded_disconnect(provider, conn)


def _report(result: ActionResult) -> None:
    if result.message:
        if result.success:
            notify("VPN", result.message)
        else:
            notify("VPN — Error", result.message, urgent=True)
    refresh_bar()


def _happ_rejected_rows(shown: set[str]) -> list[tuple[str, Callable]]:
    """Subscriptions whose panel answered stub rows instead of servers
    (device limit reached, client not supported) — say why in the panel's
    own words instead of silently missing from the list."""
    rows: list[tuple[str, Callable]] = []
    for sub_id, prov in happmeta.providers().items():
        if prov["name"] in shown or not (reasons := happmeta.subscription_rejection(sub_id)):
            continue
        name = prov["name"]
        rows.append(
            (
                f"⚠️ {name}: {reasons[0].removeprefix('⚠️').strip()}",
                lambda n=name, r=reasons: _happ_rejected(n, r),
            )
        )
    return rows


def _happ_rejected(name: str, reasons: list[str]) -> ActionResult:
    notify(f"Happ — {name} sent no servers", "\n".join(reasons))
    return ActionResult(True, "")


def _happ_no_headers() -> ActionResult:
    """Subscriptions are fetched with happmeta.default_headers() until
    ~/.config/happ-capture/headers.json exists; a panel with a device limit
    rejects those, and an empty list looked like the menu had lost every
    provider."""
    notify(
        "Happ — no servers",
        "The provider didn't return servers for Happ's default headers.\n"
        "Refresh subscriptions; if still empty, capture the device headers once:\n"
        'omarchy-vpn README → "Happ setup (one-time, for headless)"\n'
        f"(writes {happmeta.HEADERS_FILE})",
    )
    return ActionResult(True, "")


def _refresh_subscriptions() -> ActionResult:
    """Manual Happ subscription refresh — fire-and-forget (fetches can take
    tens of seconds); the menu rebuilds with fresh servers on next open.
    Forced like Refresh All: the gated --update-subs skipped every cache
    younger than SUB_MAX_AGE, so a click right after a fetch did nothing
    (a freed device slot stayed "device limit reached" for up to an hour)."""
    subprocess.Popen(
        [sys.executable, str(Path(__file__)), "--update-subs-force"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    notify("Happ", "Subscription refresh started — reopen the menu in a few seconds")
    return ActionResult(True, "")


def _traffic_summary(info: dict | None) -> str | None:
    """'6.5 GB / ∞ · until 20.10.2026' from the panel's userinfo headers."""
    if not info:
        return None
    parts = []
    traffic = happmeta.fmt_traffic(info.get("download"))
    limit = happmeta.fmt_limit(info.get("total"))
    if traffic != "?" or limit != "∞":
        parts.append(f"{traffic} / {limit}")
    expire = happmeta.fmt_expire(info.get("expire"))
    if expire != "?":
        parts.append(f"until {expire}")
    return " · ".join(parts) or None


def subscription_report(failed: dict[str, str]) -> tuple[str, str]:
    """(title, body) after a manual refresh: per Happ provider its ping
    summary (cached sweep, like the menu row) and the panel's traffic;
    a provider that didn't update gets ⚠️ and why — its old list stays."""
    names_by_sub: dict[str, list[str]] = {}
    for server in happmeta.all_servers(allow_fetch=False):
        names_by_sub.setdefault(server["provider_id"], []).append(server["name"])
    lines = []
    for sub_id, prov in happmeta.providers().items():
        if not prov.get("url"):
            continue
        name = prov["name"]
        names = names_by_sub.get(sub_id, [])
        details = [
            happmeta.provider_ping_summary(names) or f"{len(names)} servers, no ping yet",
            _traffic_summary(happmeta.subscription_info(sub_id)),
        ]
        line = f"{name}: " + " · ".join(d for d in details if d)
        if name in failed:
            line = f"⚠️ {line}\n    not updated: {failed[name]}"
        lines.append(line)
    title = (
        f"Happ — {len(failed)} subscription(s) not updated"
        if failed
        else "Happ — subscriptions updated"
    )
    return title, "\n".join(lines) or "No Happ subscriptions"


def happ_provider_menu(provider, pname: str, entries: list) -> ActionResult:
    """Happ level 3: servers of one provider with ping + protocol info."""
    if not entries:
        notify("Happ", f"{pname}: no servers")
        return ActionResult(True, "")
    items: list[tuple[str, Callable]] = []

    # Panel card info (traffic/expiry) from the subscription cache — the
    # first "ⓘ" entry only notifies, it is not connectable.
    sub_id = next((e.get("provider_id") for e in entries if e.get("provider_id")), None)
    info = happmeta.subscription_info(sub_id) if sub_id else None
    if info:
        parts = []
        traffic = happmeta.fmt_traffic(info.get("download"))
        limit = happmeta.fmt_limit(info.get("total"))
        if traffic != "?" or limit != "∞":
            parts.append(f"Traffic {traffic} / {limit}")
        expire = happmeta.fmt_expire(info.get("expire"))
        if expire != "?":
            parts.append(f"until {expire}")
        if parts:
            lines = []
            if info.get("title"):
                lines.append(str(info["title"]))
            lines.append(
                f"↓ {happmeta.fmt_traffic(info.get('download'))} · "
                f"↑ {happmeta.fmt_traffic(info.get('upload'))} / "
                f"{happmeta.fmt_limit(info.get('total'))}"
            )
            if expire != "?":
                lines.append(f"Valid until {expire}")

            def _info_action():
                notify(f"Happ · {pname}", "\n".join(lines))
                return ActionResult(True, "")

            items.append(("ⓘ " + " · ".join(parts), _info_action))

    for entry in entries:
        conn = VPNConnection(
            name=entry["name"],
            provider="Happ",
            active=entry["active"],
            subscription_id=entry.get("provider_id"),
            subscription_name=pname,
        )
        label = f"Disconnect {conn.name}" if conn.active else conn.name
        suffix = happmeta.server_info_suffix(conn.name, entry.get("protocol", ""))
        if suffix:
            label += f"    {suffix}"
        if conn.active:
            items.append((label, lambda c=conn: guarded_disconnect(provider, c)))
        else:
            items.append((label, lambda c=conn: guarded_connect(provider, c)))
    items.append((BACK_LABEL, lambda: happ_menu(provider)))
    run_items(_unique_labels(items), prompt=pname[:40])
    return ActionResult(True, "")


def _unique_labels(items: list[tuple[str, Callable]]) -> list[tuple[str, Callable]]:
    """Disambiguate repeated labels so every menu entry stays reachable.

    Two servers can render identically (same remarks + same info suffix) and
    the menu returns the picked label text — without this the later entry could never
    be selected. First occurrence keeps its label; repeats get " (2)", " (3)"…"""
    seen: set[str] = set()
    counts: dict[str, int] = {}
    unique = []
    for label, action in items:
        if label not in seen:
            seen.add(label)
            unique.append((label, action))
            continue
        # loop the suffix upward: a generated " (2)" can collide with a
        # genuine later label like "Same (2)"
        n = counts.get(label, 1) + 1
        candidate = f"{label} ({n})"
        while candidate in seen:
            n += 1
            candidate = f"{label} ({n})"
        counts[label] = n
        seen.add(candidate)
        unique.append((candidate, action))
    return unique


def run_items(items: list[tuple[str, Callable]], prompt: str) -> ActionResult:
    """Show one menu, run the chosen action, notify + refresh the bar widget."""
    if not items:
        notify("VPN", "Nothing available")
        return ActionResult(False, "nothing available")

    selected = menu_select([label for label, _ in items], prompt=prompt)
    if not selected:
        return ActionResult(True, "")

    # match the label as menu_select() sent it (TAB/newlines flattened),
    # stripped-to-stripped: labels like "  Import …" keep their indent for
    # display only, so no two labels may differ only in surrounding
    # whitespace.
    selected = selected.strip()
    action = next((fn for label, fn in items if _menu_option(label).strip() == selected), None)
    if action is None:
        logutil.log(f"menu [{prompt}]: no action matches [{selected!r}]")
        return ActionResult(True, "")

    result: ActionResult = action()
    logutil.log(f"menu [{prompt}]: [{selected}] -> success={result.success}: {result.message}")
    if result.message:
        if result.success:
            notify("VPN", result.message)
        else:
            notify("VPN — Error", result.message, urgent=True)

    refresh_bar()
    return result


MENU_TIMEOUT = 300  # seconds — omarchy-menu-select waits for its done-file forever
# omarchy.menu's dmenu card is 300 units wide by default — server names with
# ping/protocol info and DNS-leak resolver rows get cut off at that width.
MENU_WIDTH = 640
MENU_MAX_HEIGHT = 560
MENU_SIZE_ARGS = ["--", "--width", str(MENU_WIDTH), "--maxheight", str(MENU_MAX_HEIGHT)]
_MENU_UNSAFE = re.compile(r"[\t\r\n]+")


def _menu_option(label: str) -> str:
    """omarchy.menu splits an option on TAB into glyph/label/subtext, and a
    subscription can name a server anything — flatten TAB/newlines so a
    label is always shown (and returned) as one plain label."""
    return _MENU_UNSAFE.sub(" ", label)


def _run_menu_cmd(cmd: list[str], what: str) -> str | None:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=MENU_TIMEOUT, check=False
        )
    except subprocess.TimeoutExpired:
        logutil.log(f"{cmd[0]} timed out after {MENU_TIMEOUT}s")
        subprocess.run(["omarchy-shell", "-q", "shell", "hide", "omarchy.menu"], check=False)
        return None
    except FileNotFoundError:
        notify("VPN — Error", f"{cmd[0]} not found — omarchy-vpn needs Omarchy 4", urgent=True)
        return None
    # exit 1 = dismissed (Esc / click outside); stdout is the picked label only
    selected = result.stdout.rstrip("\n") if result.returncode == 0 else ""
    if not selected:
        logutil.log(f"menu {what}: no selection")
    return selected or None


def menu_select(options: list[str], prompt: str = "VPN") -> str | None:
    """One omarchy.menu list (omarchy-menu-select); the picked label or None."""
    if not options:
        return None
    return _run_menu_cmd(
        ["omarchy-menu-select", prompt, *map(_menu_option, options), *MENU_SIZE_ARGS],
        f"[{prompt}]",
    )


def menu_input(prompt: str) -> str | None:
    """Single-field text input (omarchy-menu-input). None on any failure or
    empty input."""
    text = _run_menu_cmd(
        ["omarchy-menu-input", prompt, "--width", str(MENU_WIDTH)], f"input [{prompt}]"
    )
    return text.strip() or None if text else None


def import_config_file(provider, title: str) -> ActionResult:
    path = menu_input(f"{title} config path")
    if not path:
        return ActionResult(success=False, message="No path entered")
    return provider.import_config(path)


def run_menu():
    menu_loop()


# ── Helpers ───────────────────────────────────────────────────────────────────


def _collect_ping_targets() -> list[tuple[str, str, int]]:
    """Happ + every provider's ping targets for one --update-ping sweep.

    One broken provider must not stop the others (pattern:
    happmeta.update_subscriptions), so a raising ping_targets() is skipped."""
    targets = happmeta.ping_targets()
    for provider in ALL_PROVIDERS:
        try:
            targets += provider.ping_targets()
        except Exception as e:  # noqa: BLE001 — one broken provider must not stop the rest
            logutil.log(f"ping targets: {provider.name} skipped: {e!r}")
            continue
    return targets


def notify(title: str, message: str, urgent: bool = False):
    # title/message can carry a VPN daemon's own error text or a
    # subscription provider's server name — notifyutil cleans both
    notifyutil.send(title, message, urgent=urgent)


def refresh_bar():
    """Re-run the bar widget's --status now instead of on its next tick.
    -q: best effort — no shell running, or the widget not on the bar, is fine."""
    with contextlib.suppress(OSError, subprocess.TimeoutExpired):
        subprocess.run(
            ["omarchy-shell", "-q", PLUGIN_ID, "refresh"],
            capture_output=True,
            timeout=5,
            check=False,
        )


# ── Main ──────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--status", action="store_true", help="Print JSON status for the bar widget")
    group.add_argument("--menu", action="store_true", help="Open interactive menu")
    group.add_argument(
        "--disconnect-all", action="store_true", help="Disconnect every VPN (the panel's switch)"
    )
    group.add_argument(
        "--servers", action="store_true", help="Print the panel's server list as JSON"
    )
    group.add_argument(
        "--connect",
        nargs="+",
        metavar="PROVIDER NAME [SUBSCRIPTION_ID]",
        help="Connect a server (the panel's server list)",
    )
    group.add_argument(
        "--disconnect", nargs=2, metavar=("PROVIDER", "NAME"), help="Disconnect a connection"
    )
    group.add_argument(
        "--dns-leak-test", action="store_true", help="Run the DNS leak test (the panel's DNS badge)"
    )
    group.add_argument(
        "--dns-autotest",
        action="store_true",
        help="Silent DNS leak test after a connect (internal, config dns_autotest)",
    )
    group.add_argument(
        "--update-ip",
        metavar="CONN_NAME",
        help="Refresh exit-IP cache in the background (internal)",
    )
    group.add_argument(
        "--happ-keeper",
        nargs="*",
        metavar="SERVER [SUBSCRIPTION_ID]",
        help="Hold the happd session that owns the xray process (internal)",
    )
    group.add_argument(
        "--keys-keeper",
        nargs=2,
        metavar=("KIND", "SERVER_ID"),
        help="Hold the happd session that owns a key xray process (internal)",
    )
    group.add_argument(
        "--update-ping",
        action="store_true",
        help="Refresh Happ server ping cache in the background (internal)",
    )
    group.add_argument(
        "--update-subs",
        action="store_true",
        help="Refresh Happ subscription caches in the background (internal)",
    )
    group.add_argument(
        "--update-subs-force",
        action="store_true",
        help="Like --update-subs but bypassing the SUB_MAX_AGE cache gate (Refresh All)",
    )
    group.add_argument(
        "--update-reputation",
        action="store_true",
        help="Refresh server IP-reputation cache in the background (internal)",
    )
    group.add_argument(
        "--settings",
        action="store_true",
        help="Settings list in this terminal (what 🛠 Tools → ⚙ Settings opens)",
    )
    group.add_argument(
        "--configure",
        action="store_true",
        help="Interactive setup wizard: providers, tools, IP sources/keys",
    )
    args = parser.parse_args()
    if args.keys_keeper is not None and args.keys_keeper[0] not in ("ss", "vless"):
        kind = args.keys_keeper[0]
        parser.error(f"argument --keys-keeper: invalid KIND {kind!r} (choose from 'ss', 'vless')")

    if args.status:
        print(json.dumps(get_status()))
    elif args.menu:
        run_menu()
    elif args.servers:
        print(json.dumps(server_list(), ensure_ascii=False))
    elif args.connect is not None:
        if len(args.connect) not in (2, 3):
            parser.error("--connect takes PROVIDER NAME [SUBSCRIPTION_ID]")
        _report(panel_connect(*args.connect))
    elif args.disconnect is not None:
        _report(panel_disconnect(*args.disconnect))
    elif args.disconnect_all:
        result = disconnect_all()
        notify("VPN", result.message, urgent=not result.success)
        refresh_bar()
    elif args.dns_leak_test:
        dns_leak_test_menu()
        refresh_bar()
    elif args.dns_autotest:
        run_dns_autotest()
    elif args.update_ip:
        ipinfo.update(args.update_ip)
    elif args.update_ping:
        # pings go straight out the NIC (happmeta.measure_ping), which the
        # killswitch drops: a sweep now would mark every server unreachable —
        # keep the last real values and let them age out instead
        if killswitch.is_enabled():
            logutil.log("ping sweep skipped: killswitch is on")
        elif not _single_flight(PING_LOCK):
            pass  # every --status tick spawns one while the cache is stale
        else:
            happmeta.write_pings(_collect_ping_targets())
    elif args.update_reputation:
        reputation.write_reputations(_collect_ping_targets())
    elif args.update_subs:
        happmeta.update_subscriptions()
    elif args.update_subs_force:
        # a manual refresh (menu or Refresh All) runs in the background:
        # report every provider — a silent failure looked like success
        failed = happmeta.update_subscriptions(force=True)
        notify(*subscription_report(failed))
    elif args.happ_keeper is not None:
        run_happ_keeper(*args.happ_keeper[:2])
    elif args.keys_keeper is not None:
        run_keys_keeper(*args.keys_keeper)
    elif args.settings:
        run_settings_window()
    elif args.configure:
        run_configure_wizard(TerminalPrompter())


if __name__ == "__main__":
    main()
