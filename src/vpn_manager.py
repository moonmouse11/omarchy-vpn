#!/usr/bin/env python3
"""
omarchy-vpn — entry point
Usage:
  vpn_manager.py --status   Output JSON status for the omarchy-shell bar widget
"""

import argparse
import contextlib
import fcntl
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import NamedTuple, NoReturn

sys.path.insert(0, str(Path(__file__).parent))

import config
import delayping
import dnsleak
import fsutil
import happmeta
import ipinfo
import ipv6guard
import killswitch
import logutil
import notifyutil
import providers.happ as happ_provider
import quickconnect
import reputation
import settings_tui
import speedtest
from providers import ALL_PROVIDERS
from providers.base import (
    ActionResult,
    VPNConnection,
    iface_rate,
    iface_traffic,
    run_helper,
    sample_iface_traffic,
)
from providers.happ import run_keeper as run_happ_keeper
from providers.keys import KeysProvider
from providers.keys import run_keeper as run_keys_keeper

PLUGIN_ID = "omarchy-vpn"  # omarchy-shell plugin id == its IPC target (manifest.json)


def visible_providers() -> list:
    """Providers not hidden in the user config."""
    cfg = config.load_config()
    return [p for p in ALL_PROVIDERS if cfg.provider_visible(p.name)]


def active_connections(providers=None) -> list[VPNConnection]:
    """What is tunneled right now — every provider by default, hidden ones too:
    ⚙ Settings hides a protocol from the server list, not a tunnel it has up
    (the bar, the checks and the guards must all see the same thing)."""
    return [
        conn
        for provider in (providers or ALL_PROVIDERS)
        for conn in provider.connections()
        if conn.active
    ]


# ── Status ────────────────────────────────────────────────────────────────────


def get_status() -> dict:
    """Aggregate ALL active connections across providers.

    Waybar-style classes: "vpn-connected" + "vpn-<provider>" per active provider,
    "vpn-disconnected" when nothing is up. Tooltip lists every active
    connection with per-interface traffic stats.
    """
    cfg = config.load_config()
    # every provider, hidden ones too: ⚙ Settings hides a protocol from the
    # server list, but a tunnel it has up (autostart, NM) is still a tunnel
    active = active_connections(providers=list(ALL_PROVIDERS))
    _enforce_ipv6_guard(active, cfg)

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


# The bar label's labelFormat placeholders (Widget.qml fills them).
LABEL_FIELDS = (
    "label", "provider", "subscription", "server", "count", "state",
    "exit_ip", "exit_country", "exit_flag",
    "rate", "down", "up", "total", "total_down", "total_up",
    "ping", "protocol", "interface", "sub_traffic", "sub_expire",
    "dns", "ipv6", "killswitch", "activity",
)  # fmt: skip


def _split_arrows(text: str) -> tuple[str, str]:
    """ "↓ 3 KiB/s ↑ 4 KiB/s" -> ("3 KiB/s", "4 KiB/s"); ("", "") when absent."""
    down, _, up = text.partition("↑")
    return down.replace("↓", "").strip(), up.strip()


def activity_text() -> str:
    """What the plugin is busy with, for the bar: "ping 23/150" while the
    Ping button's sweep runs, else "". One small file read per tick."""
    progress = delayping.read_progress()
    if progress is None:
        return ""
    return f"ping {progress.get('done', 0)}/{progress.get('total', 0)}"


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
    fields["activity"] = activity_text()
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
    ms = happmeta.ping_ms(happmeta.ping_key(first.name, first.subscription_id))
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


def _window_tools(active: list[VPNConnection], cfg) -> list[str]:
    """The app window's Tools buttons: what ⚙ Settings didn't hide (Settings
    itself can't be), the kill switch only where it works."""
    keys = [k for k, _label, _fn in TOOLS if k == "settings" or cfg.tool_visible(k)]
    if cfg.tool_visible("killswitch") and not _killswitch_unsupported(active):
        keys.append("killswitch")
    return keys


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
            "key_hints": cfg.panel_key_hints,
            "tools": _window_tools(active, cfg),
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
    if ipv6_off:
        ipv6_badge = _badge("ipv6", "IPv6 blocked", "ok", "IPv6 is off while the VPN is up")
    else:
        why = "" if cfg.ipv6_guard else " — IPv6 guard is off in ⚙ Settings"
        ipv6_badge = _badge("ipv6", "IPv6 leaks", "bad", f"IPv6 is on and bypasses the tunnel{why}")
    badges = [_exit_badge(first, cfg.exit_ip_max_age), _dns_badge(first), ipv6_badge]
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
    # the pill names the provider: "Happ · Provider B: 🇩🇪 X" / "WireGuard: nl" -> the rest
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
        "key_hints": cfg.panel_key_hints,
        "tools": _window_tools(active, cfg),
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
CHECK_FLAGS = ("--dns-autotest", "--check", "--update-ip")


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


# held by whoever measures pings now: a Ping-all run or the queue's worker
# (_try_lock / ping_now). Once seven background sweeps ran at once, each
# spawned by a 3 s tick before the first could finish (2026-10-13).
PING_LOCK = Path.home() / ".cache/vpn-manager/ping.lock"


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
            down = _disconnect_all(for_switch=True)  # already under SWITCH_LOCK
            if not down.success:
                _sync_ipv6_guard()  # the teardown may have dropped everything anyway
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
        if cfg.ipv6_guard:
            _apply_ipv6_guard(ipv6guard.disable())
        else:
            _sync_ipv6_guard()
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
    guard = config.load_config().ipv6_guard  # ⚙ off: IPv6 stays (or comes back) on
    if guard and active_connections(providers=list(ALL_PROVIDERS)):
        _apply_ipv6_guard(ipv6guard.disable())
    else:
        _apply_ipv6_guard(ipv6guard.enable())


def _enforce_ipv6_guard(active: list[VPNConnection], cfg) -> None:
    """--status: a tunnel that came up without the plugin (WireGuard autostart
    at boot, the Happ app, NM) gets IPv6 turned off too — the guard used to
    run only inside the plugin's own connect/disconnect. Logged, not notified:
    a failing sudo would otherwise raise a bubble every tick."""
    if active and cfg.ipv6_guard and not ipv6guard.is_disabled():
        guard = ipv6guard.disable()
        logutil.log(f"ipv6 guard: a tunnel is up, IPv6 off: {guard.success} {guard.message}")


def sync_ipv6_boot() -> ActionResult:
    """⚙ IPv6 guard at boot: a systemd drop-in turns IPv6 off before every
    autostarted WireGuard/AmneziaWG tunnel (they come up before login, long
    before the bar's first --status) — or no drop-ins with the guard off.
    Runs on an autostart change, a Settings save and `make install`."""
    state = "on" if config.load_config().ipv6_guard else "off"
    code, out = run_helper("ipv6-boot", state)
    return ActionResult(code == 0, "" if code == 0 else f"IPv6 at boot: {out}")


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


def _disconnect_all(for_switch: bool = False) -> ActionResult:
    """for_switch: a connect is tearing the old tunnel down — leave IPv6 off;
    the connect's own result decides (else IPv6 came back on between the old
    tunnel going down and the new one coming up)."""
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
    if not for_switch:
        _sync_ipv6_guard()
    if failed:
        return ActionResult(False, "Failed: " + ", ".join(failed))
    message = ", ".join(stopped) if stopped else "nothing was active"
    return ActionResult(True, f"Disconnected: {message}")


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


def _dns_leak_server_row(server: dict, ip_country: str = "", ip_asn: int | None = None) -> str:
    """One row per detected resolver. 'Leaked' when dnsleak.server_tags()
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
    return label


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


class CheckFailed(Exception):
    """A check ended without a result; its bubble already says why."""


def _emit(obj: dict) -> None:
    """One JSON line for the app window's check card (Widget.qml checkProc)."""
    print(json.dumps(obj, ensure_ascii=False), flush=True)


class _CheckProgress:
    """The progress bubble (notifyutil.Progress) and, for the window, one
    JSON line per step — the user wanted both."""

    def __init__(self, title: str, steps: int | None = None):
        self.bubble = notifyutil.Progress(title, steps=steps)
        self.steps = steps

    def step(self, n: int, label: str) -> None:
        self.bubble.step(n, label)
        _emit({"step": n, "steps": self.steps, "label": label})

    def done(self, text: str) -> None:
        self.bubble.done(text)

    def fail(self, text: str) -> NoReturn:
        self.bubble.fail(text)
        raise CheckFailed(text)


def _check_rows(texts: list[str]) -> list[dict]:
    """Result rows for the card; a row that reports a leak or a failure is
    "bad" (the same words the old menu rows carried)."""
    return [
        {"text": t, "state": "bad" if "Leaked" in t or ": ✗ " in t or t.startswith("⚠") else ""}
        for t in texts
    ]


CHECK_TITLES = {"dns": "DNS Leak Test", "ip": "IP Info", "speed": "Speed Test"}
CANCELLED = "Cancelled — the connection changed"


def run_check(kind: str, target: str | None = None) -> ActionResult:
    """--check dns|ip|speed [TARGET]: one check for the app window's card —
    JSON lines on stdout ({step, steps, label}…, then {result} or {error};
    a bare `--check speed` answers {choices}) plus the usual progress bubble.
    A switch SIGTERMs it (CHECK_FLAGS): it would test the server being left."""
    title = CHECK_TITLES[kind]
    steps: int | None = {"dns": len(dnsleak.STEPS), "ip": 2}.get(kind)
    targets: list[tuple[str, str]] = []
    duration = speedtest.DURATION
    if kind == "speed":
        if target is None:
            _emit({"choices": _speed_choices()})
            return ActionResult(True, "")
        try:
            targets, duration = _speed_targets(target)
        except CheckFailed as e:
            _emit({"error": str(e)})
            return ActionResult(False, "")  # the card says it; no second bubble
        steps = len(targets) if len(targets) > 1 else None
    progress = _CheckProgress(title, steps)
    previous = signal.signal(signal.SIGTERM, _cancel_check)
    try:
        if kind == "dns":
            result = _dns_check(progress)
        elif kind == "ip":
            result = _ip_check(progress)
        else:
            result = _speed_check(progress, targets, duration)
    except CheckFailed as e:
        _emit({"error": str(e)})
        return ActionResult(False, "")  # already notified, with the reason
    except CheckCancelled:
        logutil.log(f"{title} cancelled: the connection changed")
        progress.done(CANCELLED)
        _emit({"error": CANCELLED})
        return ActionResult(False, "")
    finally:
        signal.signal(signal.SIGTERM, previous)
    _emit({"result": {"title": title, **result}})
    return ActionResult(True, "")


def _dns_check(progress: _CheckProgress) -> dict:
    """DNS leak test — same backend (bash.ws) as dnsleaktest.com — plus our
    own checks around bash.ws's conclusion (exit country, IPv6, resolvers)."""
    try:
        result = dnsleak.run(on_step=lambda n, label: progress.step(n, f"{label}…"))
    except dnsleak.LeakTestError as e:
        progress.fail(f"Test {e}{_failure_hint(e.reason)}")
    progress.done("Done")

    active = active_connections()
    ip_country, ip_asn = result["ip_country"], result.get("ip_asn")
    texts = []
    if result["ip"]:
        texts.append(f"IP: {result['ip']} {ipinfo.flag_emoji(ip_country)}".strip())
    texts.append(_dns_leak_exit_row(ip_country, active, result["ip"]))
    texts.append(_dns_leak_ipv6_row(bool(active)))
    if result["dns_servers"]:
        texts.extend(_dns_leak_server_row(s, ip_country, ip_asn) for s in result["dns_servers"])
    else:
        texts.append("No DNS servers found")
    verdict = _dns_leak_verdict_row(result)
    _save_dns_verdict(active, verdict)
    if verdict:
        texts.append(verdict)
    if result["conclusion"]:
        texts.append(f"bash.ws: {result['conclusion']}")
    rows = _check_rows(texts)
    bad = any(r["state"] == "bad" for r in rows)
    state = "bad" if bad else ("ok" if verdict else "unknown")
    # lead with a verdict line (exit, IPv6, resolvers), not one resolver's row
    text = next((r["text"] for r in rows if r["text"].startswith("Leaked")), verdict)
    return {
        "summary": {"state": state, "text": text or "No verdict: the exit IP is unknown"},
        "rows": rows,
    }


def _ip_info_flag_row(label: str, value: bool | None) -> str:
    return f"{label}: {'Yes' if value else 'No'}"


def _ip_check(progress: _CheckProgress) -> dict:
    """Multi-source exit-IP report — one row per enabled ipsources source
    (free ones on by default; keyed ones once their API key is set). A single
    ad-hoc lookup for the current public IP, not the background sweep."""
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
    progress.done("Done")

    texts = [f"IP: {findings[0].ip}"]
    for finding in findings:
        parts = [p for p in (finding.country_name, finding.org) if p]
        if finding.abuse_score is not None:
            parts.append(f"abuse {finding.abuse_score}/100")
        texts.append(f"{finding.source}: {' · '.join(parts)}" if parts else finding.source)
    texts.append(_ip_info_flag_row("🏢 Datacenter/Hosting", any(f.hosting for f in findings)))
    texts.append(_ip_info_flag_row("🕵️ Proxy/VPN detected", any(f.proxy for f in findings)))
    texts.append(_ip_info_flag_row("📱 Mobile network", any(f.mobile for f in findings)))
    first = findings[0]
    where = " · ".join(p for p in (first.country_name, first.org) if p)
    return {
        "summary": {"state": "", "text": f"{first.ip} · {where}" if where else first.ip},
        "rows": _check_rows(texts),
    }


SPEED_TEST_ALL_LABEL = "🌍 All services"
SPEED_TEST_MAX_URLS = 5  # remembered custom URLs, newest first
# per service in "All services" — run one after another (in parallel they'd
# split the same uplink and each report a fraction of it), so this keeps
# the whole sweep around half a minute
SPEED_TEST_ALL_DURATION = 5.0


def _speed_targets_all() -> list[tuple[str, str]]:
    """Public presets, then custom URLs remembered in config.json
    (`speed_test_urls` — e.g. a test stand's own file server)."""
    targets = [(s.name, s.url) for s in speedtest.SERVICES]
    preset_urls = {s.url for s in speedtest.SERVICES}
    targets += [
        (url, url)
        for url in config.load_config().speed_test_urls
        if url not in preset_urls  # its preset row already covers it
    ]
    return targets


def _speed_choices() -> list[dict]:
    """What the card offers before a speed test: every service, each one,
    and (in the card itself) a custom URL field."""
    preset = {s.name for s in speedtest.SERVICES}
    return [{"key": "all", "label": SPEED_TEST_ALL_LABEL}] + [
        {"key": name, "label": f"{'🌐' if name in preset else '🔗'} {name}"}
        for name, _url in _speed_targets_all()
    ]


def _speed_targets(target: str) -> tuple[list[tuple[str, str]], float]:
    """`all`, a preset's name or a remembered URL — else a new custom URL,
    remembered (newest first) once it is a valid http(s) URL."""
    every = _speed_targets_all()
    if target == "all":
        return every, SPEED_TEST_ALL_DURATION
    known = [(name, url) for name, url in every if target == name]
    if known:
        return known, speedtest.DURATION
    if not speedtest.is_valid_url(target):
        raise CheckFailed(f"Not an http(s) URL: {target}")
    cfg = config.load_config()
    cfg.speed_test_urls = [target, *(u for u in cfg.speed_test_urls if u != target)][
        :SPEED_TEST_MAX_URLS
    ]
    config.save_config(cfg)
    return [(target, target)], speedtest.DURATION


def _speed_check(progress: _CheckProgress, targets: list[tuple[str, str]], duration: float) -> dict:
    """Download throughput through whatever the current route is (tunnel or,
    with no VPN up, the plain uplink), one target after another."""
    results = []
    for i, (name, url) in enumerate(targets, 1):
        progress.step(i, f"{name}: measuring for ~{duration:.0f} s…")
        results.append((name, speedtest.measure(url, duration)))

    active = active_connections()
    texts = [
        _speed_test_route_row(active),
        *(_speed_test_result_row(name, m) for name, m in results),
    ]
    ok = [(name, m.mbps) for name, m in results if m.mbps is not None]
    if not ok:
        first = next(m.error for _name, m in results if m.error)
        progress.fail(f"All {len(results)} failed — {first}{_failure_hint(first)}")
    progress.done(f"Done — {len(ok)}/{len(results)} measured")
    best = max(ok, key=lambda r: r[1])
    if len(results) > 1:
        texts.append(f"🏆 Fastest: {best[0]} ({best[1]:.1f} Mbit/s)")
    return {
        "summary": {"state": "ok", "text": f"{best[0]}: ⬇ {best[1]:.1f} Mbit/s"},
        "rows": _check_rows(texts),
    }


def _speed_test_route_row(active: list[VPNConnection]) -> str:
    if not active:
        return "Route: direct (no VPN)"
    return "Route: " + ", ".join(c.label for c in active)


def _speed_test_result_row(name: str, m: speedtest.Measurement) -> str:
    if m.mbps is not None:
        return f"{name}: ⬇ {m.mbps:.1f} Mbit/s"
    return f"{name}: ✗ {m.error}"


def run_tool(key: str) -> ActionResult:
    """--tool KEY: one of the app window's Tools buttons."""
    if key == "killswitch":
        if _killswitch_unsupported(active_connections(providers=list(ALL_PROVIDERS))):
            msg = "The kill switch is suspended while a NetworkManager VPN is up"
            return ActionResult(False, msg)
        on = killswitch.is_enabled() or killswitch.mode() in ("happ", "all")
        return _killswitch_toggle(not on)
    return next(fn for k, _label, fn in TOOLS if k == key)()


# The window's "+ Import": a config file, or a pasted key (Happ: its own app)
IMPORT_KINDS = {
    "WireGuard": "file",
    "AmneziaWG": "file",
    "OpenVPN": "file",
    "NetworkManager": "file",
    "VLESS": "key",
    "Shadowsocks": "key",
}
IMPORT_EXTENSIONS = {"OpenVPN": "ovpn conf", "NetworkManager": "conf ovpn"}  # else "conf"
# right click on a server: Toggle autostart / Delete
MANAGED_PROVIDERS = ("WireGuard", "AmneziaWG", "NetworkManager")
FILE_SELECT_TIMEOUT = 660  # omarchy-file-select gives up on an unanswered chooser at 600 s


def run_import(provider_name: str, source: str | None = None) -> ActionResult:
    """--import PROVIDER [PATH | -]: the window's "+ Import". No PATH opens the
    desktop file chooser (omarchy-file-select, through the portal); "-" reads
    a key or path from stdin — a key in argv would show in `ps`."""
    provider = _provider_named(provider_name)
    if provider is None or provider_name not in IMPORT_KINDS:
        return ActionResult(False, f"{provider_name}: import not supported")
    if source == "-":
        source = sys.stdin.read()
    elif source is None:
        cmd = [
            "omarchy-file-select",
            "--title",
            f"Import {provider_name} config",
            "--extensions",
            IMPORT_EXTENSIONS.get(provider_name, "conf"),
        ]
        try:
            picked = subprocess.run(
                cmd, check=False, capture_output=True, text=True, timeout=FILE_SELECT_TIMEOUT
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            return ActionResult(False, f"File chooser failed: {e}")
        if picked.returncode == 1:  # nothing picked: the user's decision, no bubble
            return ActionResult(True, "")
        if picked.returncode != 0:
            return ActionResult(False, f"File chooser failed: {picked.stderr.strip()}")
        source = picked.stdout.splitlines()[0] if picked.stdout.strip() else ""
    source = source.strip()
    if not source:
        return ActionResult(False, "Nothing to import")
    return provider.import_config(source)


def run_profile_action(action: str, provider_name: str, name: str) -> ActionResult:
    """--profile autostart|delete PROVIDER NAME: a server row's right click.
    The providers refuse to delete an active profile themselves."""
    provider = _provider_named(provider_name)
    if provider is None or provider_name not in MANAGED_PROVIDERS:
        return ActionResult(False, f"{provider_name}: profiles can't be managed here")
    conn = next((c for c in provider.connections() if c.name == name), None)
    if conn is None:
        return ActionResult(False, f"{provider_name}: {name} not found")
    if action == "autostart":
        result = provider.toggle_autostart(conn)
        if result.success:
            boot = sync_ipv6_boot()  # the new autostart gets (or loses) its drop-in
            if not boot.success:
                return ActionResult(True, f"{result.message} — {boot.message}")
        return result
    return provider.delete_config(conn)


def _ping_scope_targets(
    scope: dict,
) -> tuple[list[tuple[str, dict]], list[tuple[str, str, int]]]:
    """(xray targets, direct targets) for a ping scope: {} = every server,
    {"group": <panel group id>}, {"server": [provider, name, subscription id]}.
    Happ/Keys go through xray (delayping); the rest keep the direct TCP connect."""
    group, server = scope.get("group"), scope.get("server")
    if server:
        pname, name, sub_id = [*server, "", "", ""][:3]
    elif group and str(group).startswith("happ:"):
        pname, name, sub_id = "Happ", None, str(group).split(":", 2)[1]
    else:
        pname, name, sub_id = group, None, None
    xray: list[tuple[str, dict]] = []
    direct: list[tuple[str, str, int]] = []
    for provider in ALL_PROVIDERS:
        if pname and provider.name != pname:
            continue
        if provider.name == "Happ":
            xray += delayping.happ_targets(sub_id if (group or server) else None, name)
        elif isinstance(provider, KeysProvider):
            xray += delayping.key_targets(provider._kind, name)
        else:
            try:
                targets = provider.ping_targets()
            except Exception as e:  # noqa: BLE001 — one broken provider must not stop the rest
                logutil.log(f"ping targets: {provider.name} skipped: {e!r}")
                continue
            direct += [t for t in targets if name is None or t[0] == name]
    return xray, direct


def _try_lock(path: Path) -> int | None:
    """A held flock's fd (release: os.close), or None when another holds it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    if _try_flock(fd):
        return fd
    os.close(fd)
    return None


def _ping_worker_alive() -> bool:
    fd = _try_lock(PING_LOCK)
    if fd is None:
        return True
    os.close(fd)
    return False


PING_REFRESH_EVERY = 2.0  # s between panel reloads while results come in (~230 ms each)


def _measure(scope: dict, kind: str) -> tuple[dict[str, dict], bool]:
    xray, direct = _ping_scope_targets(scope)
    direct_allowed = not direct or not killswitch.is_enabled()
    last = time.monotonic()

    def on_progress(done: int, total: int) -> None:
        # an open panel shows each result as it arrives — reloading its list
        # at most every PING_REFRESH_EVERY (the caller refreshes at the end)
        nonlocal last
        if done < total and time.monotonic() - last >= PING_REFRESH_EVERY:
            last = time.monotonic()
            refresh_bar()

    results = delayping.run(xray, direct, direct_allowed, kind=kind, on_progress=on_progress)
    return results, direct_allowed


def ping_now(scope: dict | None = None) -> tuple[str, str] | None:
    """--ping-now: the only way pings are measured (no background sweep —
    the user's call). Happ/Keys go through xray under happd (delayping),
    which the kill switch lets through; WireGuard/OpenVPN keep the direct
    TCP connect, which it drops — skipped while it is on.

    No scope: the Ping button for everything — refused while anything is
    measured. A row's or a group's scope (click on its ping, or `p`) goes
    into a queue, never twice, and is refused while Ping-all runs; the
    first such process becomes the worker and drains the queue one scope
    at a time (so their cache writes never race). Returns the notification,
    None for a quiet queued ping (the panel shows "…" on its rows)."""
    if not scope:
        with delayping.queue_locked():
            fd = _try_lock(PING_LOCK)
            if fd is None:
                progress = delayping.read_progress() or {}
                if progress.get("kind") == delayping.ALL:
                    return "Ping", "Already measuring — the list updates when it's done"
                return "Ping", "Wait for the queued pings to finish"
            delayping.write_queue([])  # lock was free: whatever is left is stale
            delayping.write_progress(0, 0, delayping.ALL)  # queued pings see it at once
        try:
            refresh_bar()  # the bar shows the progress ({activity}), rows "…"
            results, direct_allowed = _measure({}, delayping.ALL)
        finally:
            os.close(fd)
        refresh_bar()  # an open panel reloads its list
        answered = sum(1 for r in results.values() if r.get("ms") is not None)
        message = f"{answered}/{len(results)} servers answered"
        if not direct_allowed:
            message += " — WireGuard/OpenVPN skipped: the kill switch drops direct pings"
        return "Ping", message

    with delayping.queue_locked():
        progress = delayping.read_progress() or {}
        if progress.get("kind") == delayping.ALL:
            return "Ping", "Ping all is running — this one is measured with it"
        queue = delayping.read_queue()
        if scope not in queue:
            delayping.write_queue([*queue, scope])
        fd = _try_lock(PING_LOCK)
    refresh_bar()  # its rows show "…" while queued
    if fd is None:
        return None  # the running worker picks it up
    try:
        while True:
            with delayping.queue_locked():
                queue = delayping.read_queue()
                if not queue:
                    break
                current = queue[0]
            try:
                _measure(current, delayping.QUEUED)
            except Exception as e:  # noqa: BLE001 — one bad scope must not stall the queue
                logutil.log(f"ping {current}: {e!r}")
            with delayping.queue_locked():
                delayping.write_queue([s for s in delayping.read_queue() if s != current])
            refresh_bar()  # its result shows
    finally:
        os.close(fd)  # under no queue lock: a request added just now finds it free
    # a scope queued between the empty check and the release would wait for
    # the next click — take it now
    if delayping.read_queue():
        return ping_now(delayping.read_queue()[0])
    return None


def _ping_scope_from_args(argv: list[str]) -> dict | None:
    """--ping-now [group ID | server PROVIDER NAME [SUBSCRIPTION_ID]]."""
    if not argv:
        return {}
    if argv[0] == "group" and len(argv) == 2:
        return {"group": argv[1]}
    if argv[0] == "server" and len(argv) in (3, 4):
        return {"server": [argv[1], argv[2], argv[3] if len(argv) == 4 else ""]}
    return None


def refresh_all_menu() -> ActionResult:
    """Force a Happ subscription sync now, bypassing SUB_MAX_AGE —
    request_subscription_update() is staleness-gated and would otherwise
    no-op if the last sync was recent. Pings are not part of it: they are
    measured only by the panel's Ping button (--ping-now). Reputation is deliberately
    excluded (its own daily cadence + IPAPI_PACE already make it a
    multi-minute background job; forcing it from a menu click isn't
    "refresh now", it's "wait a while", which belongs to its own timer)."""
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
        # the IPv6 guard applies now, not on the next connect: the running
        # tunnel and the drop-ins for boot
        _sync_ipv6_guard()
        boot = sync_ipv6_boot()
        notify("VPN", "Settings saved" + ("" if boot.success else f"\n{boot.message}"))
        refresh_bar()


# single source of truth for both tools_menu()'s rows and the configure
# wizard's questions (key, label, action) — killswitch is handled
# separately in both places since its row reflects live on/off state
# (_killswitch_item()), not a fixed action function.
TOOLS = [
    # the window opens these as its check card (--check); --tool runs them
    # with the progress bubble only (speed: every service)
    ("dns_leak_test", "🔍 DNS Leak Test", lambda: run_check("dns")),
    ("ip_info", "ℹ️ IP Info", lambda: run_check("ip")),
    ("speed_test", "⚡ Speed Test", lambda: run_check("speed", "all")),
    ("refresh_all", "🔄 Refresh All", refresh_all_menu),
    ("clear_caches", "🗑️ Clear Caches", clear_caches_menu),
    ("settings", "⚙️ Settings", settings_menu),
]


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


# ── Panel: server list + connect/disconnect ───────────────────────────────────


def _server_row(entry: dict) -> dict:
    """One server for the panel. A stale ping (older than PING_MAX_AGE —
    pings are measured only on the Ping button) keeps its value with a "~"
    and stale=True — the panel dims it. "—": not measured last time
    (WireGuard/OpenVPN under the kill switch)."""
    key = happmeta.ping_key(entry["name"], entry.get("provider_id"))
    state, ms = happmeta.ping_status(key)
    if state == "none":
        ping = ""  # never measured: say nothing rather than guess
    elif state == "skipped":
        ping = "—"
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
        "ping_ms": ms if state not in ("none", "skipped") else None,
        "stale": state == "stale",
        "ping_at": happmeta.ping_at(key),
        # the flag's country code, so the filter finds "Польша" by "pl"
        "country": (_name_flag_country(entry["name"]) or "").lower(),
    }


class PingState(NamedTuple):
    """What is being measured, for the panel's "…": every server (Ping-all),
    the queued scopes, and the run in progress — its scope (the queue's
    first; None for Ping-all) and start. A row of the running scope measured
    since that start shows its result while the rest are still measured."""

    every: bool = False
    queued: tuple = ()
    current: dict | None = None
    started: float = float("inf")


NOTHING_PINGING = PingState()


def _pinging() -> PingState:
    """A queue nobody works on (its worker died) is stale: shown as nothing."""
    progress = delayping.read_progress() or {}
    started = float(progress.get("started") or float("inf"))
    if progress.get("kind") == delayping.ALL:
        return PingState(every=True, started=started)
    queue = delayping.read_queue()
    if not queue or not _ping_worker_alive():
        return PingState()
    running = progress.get("kind") == delayping.QUEUED
    return PingState(
        queued=tuple(queue),
        current=queue[0] if running else None,
        started=started if running else float("inf"),
    )


def _server_group(
    group_id: str,
    provider: str,
    title: str,
    entries: list[dict],
    sub_id=None,
    *,
    pinging: PingState = NOTHING_PINGING,
):
    group_scope = {"group": group_id}
    group_pinging = pinging.every or group_scope in pinging.queued
    rows = [_server_row(e) for e in entries]
    for row, entry in zip(rows, entries, strict=True):
        server_scope = {"server": [provider, entry["name"], entry.get("provider_id") or ""]}
        scopes = [group_scope, server_scope]
        queued = group_pinging or server_scope in pinging.queued
        in_current_run = pinging.every or pinging.current in scopes
        # measured during the run in progress: its result shows already
        row["pinging"] = queued and not (in_current_run and row["ping_at"] >= pinging.started)
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
        "pinging": group_pinging,
        "servers": rows,
    }


HAPP_NO_HEADERS_TITLE = "⚠ No servers: the provider sent none (README: Happ setup)"


def server_list() -> dict:
    """--servers: the panel's list — every visible provider's connections,
    Happ split per subscription — with ping and protocol. Cache reads only
    (it runs when the panel opens); stale subscriptions refresh in the
    background like the menu's, pings only on the Ping button."""
    happmeta.request_subscription_update()
    pinging = _pinging()
    groups: list[dict] = []
    # every visible protocol, empty ones too: the window's tree/tabs/sidebar list them
    providers: list[dict] = []
    for provider in visible_providers():
        first = len(groups)
        providers.append(
            {
                "name": provider.name,
                "importer": IMPORT_KINDS.get(provider.name),
                "manage": provider.name in MANAGED_PROVIDERS,
            }
        )
        if provider.name == "Happ":
            _servers, happ_groups = happ_server_groups(provider)
            for pname, entries in happ_groups.items():
                sub_id = entries[0].get("provider_id") or ""
                groups.append(
                    _server_group(
                        f"happ:{sub_id}:{pname}", "Happ", pname, entries, sub_id, pinging=pinging
                    )
                )
            # a panel that answered stub rows instead of servers (device limit,
            # unsupported client) says why in its own words, not missing silently
            for sub_id, prov in happmeta.providers().items():
                if prov["name"] in happ_groups or not (
                    reasons := happmeta.subscription_rejection(sub_id)
                ):
                    continue
                title = f"{prov['name']} · ⚠ {reasons[0].removeprefix('⚠️').strip()}"
                groups.append(
                    _server_group(f"happ:{sub_id}:{prov['name']}", "Happ", title, [], sub_id)
                )
            # nothing at all with default headers: a panel may want Happ's own
            if len(groups) == first and not happmeta.has_headers():
                groups.append(_server_group("happ:no-headers", "Happ", HAPP_NO_HEADERS_TITLE, []))
        else:
            try:
                conns = provider.connections()
            except Exception as e:  # noqa: BLE001 — one broken provider must not empty the list
                logutil.log(f"server list: {provider.name} skipped: {e!r}")
                conns = []
            if conns:
                entries = [{"name": c.name, "active": c.active} for c in conns]
                groups.append(
                    _server_group(
                        provider.name, provider.name, provider.name, entries, pinging=pinging
                    )
                )
        mine = groups[first:]
        providers[-1]["total"] = sum(len(g["servers"]) for g in mine)
        providers[-1]["active"] = any(g["active"] for g in mine)
    return {
        "groups": groups,
        "providers": providers,
        "layout": config.load_config().locations_layout,
        "quick": _quick_connect(groups),
    }


def _quick_connect(groups: list[dict]) -> dict:
    """QUICK CONNECT: favourites and recent servers that are still in the list
    (with their ping and state), marking each starred row `favourite`; recent
    leaves out the favourites, `last` (the power switch) doesn't."""
    quick = quickconnect.load()
    starred = {(e["provider"], e["name"], e["sub_id"]) for e in quick["favourites"]}
    index: dict[tuple, tuple[dict, dict]] = {}
    for g in groups:
        for row in g["servers"]:
            key = (g["provider"], row["name"], g["subscription_id"])
            row["favourite"] = key in starred
            index.setdefault(key, (g, row))

    def chips(entries: list[dict]) -> list[dict]:
        out = []
        for e in entries:
            hit = index.get((e["provider"], e["name"], e["sub_id"]))
            if hit:
                g, row = hit
                out.append(
                    {
                        "provider": g["provider"],
                        "name": row["name"],
                        "sub_id": e["sub_id"],
                        "group": g["title"],
                        "active": row["active"],
                        "ping": row["ping"],
                    }
                )
        return out

    recent = chips(quick["recent"])
    return {
        "favourites": chips(quick["favourites"]),
        "recent": [c for c in recent if (c["provider"], c["name"], c["sub_id"]) not in starred],
        "last": recent[0] if recent else None,
    }


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
    result = guarded_connect(provider, conn)
    if result.success:  # QUICK CONNECT's recent, and the power switch's "last server"
        quickconnect.remember(provider.name, name, sub_id if provider.name == "Happ" else None)
    return result


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
        names_by_sub.setdefault(server["provider_id"], []).append(
            happmeta.ping_key(server["name"], server["provider_id"])
        )
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
        "--tool",
        choices=[*(key for key, _label, _fn in TOOLS), "killswitch"],
        help="Run one tool (the app window's Tools buttons; killswitch toggles it)",
    )
    group.add_argument(
        "--ipv6-boot-sync",
        action="store_true",
        help="Drop-ins turning IPv6 off before autostarted tunnels (make install)",
    )
    group.add_argument(
        "--favourite",
        nargs="+",
        metavar="PROVIDER NAME [SUBSCRIPTION_ID]",
        help="Star or unstar a server (QUICK CONNECT)",
    )
    group.add_argument(
        "--import",
        dest="import_",
        nargs="+",
        metavar="PROVIDER [PATH|-]",
        help="Import a config (no PATH: file chooser; -: a key or path on stdin)",
    )
    group.add_argument(
        "--profile",
        nargs=3,
        metavar=("autostart|delete", "PROVIDER", "NAME"),
        help="Toggle a profile's autostart or delete it (a server row's right click)",
    )
    group.add_argument(
        "--check",
        nargs="+",
        metavar="dns|ip|speed [TARGET]",
        help="Run a check for the app window's card (JSON lines); speed: all|NAME|URL",
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
        "--ping-now",
        nargs="*",
        metavar="group ID | server PROVIDER NAME [SUB_ID]",
        help="Measure ping now: every server, one panel group, or one server (the panel)",
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
        help="Interactive setup wizard: protocols, features, IP sources/keys",
    )
    group.add_argument(
        "--install-wizard",
        action="store_true",
        help="install.sh: the setup wizard, then the packages still missing on fd 3",
    )
    args = parser.parse_args()
    if args.keys_keeper is not None and args.keys_keeper[0] not in ("ss", "vless"):
        kind = args.keys_keeper[0]
        parser.error(f"argument --keys-keeper: invalid KIND {kind!r} (choose from 'ss', 'vless')")

    if args.status:
        print(json.dumps(get_status()))
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
    elif args.tool:
        _report(run_tool(args.tool))
    elif args.ipv6_boot_sync:
        boot = sync_ipv6_boot()
        print(boot.message or "IPv6 at boot: in sync")
        sys.exit(0 if boot.success else 1)
    elif args.favourite is not None:
        if len(args.favourite) not in (2, 3):
            parser.error("--favourite takes PROVIDER NAME [SUBSCRIPTION_ID]")
        if args.favourite[0] == "Happ" and len(args.favourite) != 3:
            # a Happ server is (subscription, name): without it no row ever matches
            parser.error("--favourite Happ takes NAME SUBSCRIPTION_ID")
        try:
            quickconnect.toggle_favourite(*args.favourite)
            result = ActionResult(True, "")
        except OSError as e:
            result = ActionResult(False, f"Favourite not saved: {e}")
        _report(result)  # the widget reloads the list: the star and the chips
    elif args.import_ is not None:
        if len(args.import_) not in (1, 2):
            parser.error("--import takes PROVIDER [PATH|-]")
        _report(run_import(*args.import_))
    elif args.profile is not None:
        if args.profile[0] not in ("autostart", "delete"):
            parser.error("--profile takes autostart|delete PROVIDER NAME")
        _report(run_profile_action(*args.profile))
    elif args.check is not None:
        if args.check[0] not in CHECK_TITLES or len(args.check) > 2:
            parser.error("--check takes dns|ip|speed [TARGET]")
        _report(run_check(*args.check))
    elif args.dns_autotest:
        run_dns_autotest()
    elif args.update_ip:
        ipinfo.update(args.update_ip)
    elif args.ping_now is not None:
        scope = _ping_scope_from_args(args.ping_now)
        if scope is None:
            print("--ping-now: group ID | server PROVIDER NAME [SUB_ID]", file=sys.stderr)
            sys.exit(2)
        if (note := ping_now(scope)) is not None:
            notify(*note)
    elif args.update_reputation:
        reputation.write_reputations(_collect_ping_targets())
    elif args.update_subs:
        # unattended (every minute while fetches fail): no bubble, one log line per new reason
        before = happmeta.last_subs_failures()
        for name, why in happmeta.update_subscriptions().items():
            if before.get(name) != why:
                logutil.log(f"subscription {name} not updated: {why}")
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
    elif args.configure or args.install_wizard:
        import installwizard  # noqa: PLC0415 — install-time only: not on the 3 s --status path

        out = None
        if args.install_wizard:
            # only install.sh's fd 3: write_text would truncate any other file behind it
            try:
                if os.environ.get("OMARCHY_VPN_WIZARD_FD") != "3":
                    raise OSError
                os.fstat(3)
            except OSError:
                # before any question: config.json stays untouched
                sys.exit("--install-wizard writes to fd 3: run install.sh (3>FILE)")
            out = installwizard.WIZARD_OUT
        sys.exit(installwizard.run(installwizard.TerminalPrompter(), out))


if __name__ == "__main__":
    main()
