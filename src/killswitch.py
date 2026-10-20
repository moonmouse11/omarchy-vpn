"""Killswitch integration for the VPN menu.

Wraps the /usr/local/bin/happ-killswitch script (installed root-owned by
install.sh, driven via a NOPASSWD sudoers rule, so menu actions never
block on a password prompt).

The nft table `inet happ-ks` blocks all outbound traffic except the VPN
tunnel interfaces (happ-*, plus --iface extras), DNS (dport 53), local
networks and the VPN server IPs (Happ detect conf + endpoint IPs passed
as arguments).

Three modes (persisted in the user config):
  "off"  — killswitch managed manually, no auto behaviour
  "happ" — auto: enabled alongside Happ only
  "all"  — auto: enabled for every connect; WireGuard/OpenVPN endpoints
           are resolved from their configs and whitelisted (the menu
           toggle uses this mode). NetworkManager is not parsed yet —
           the killswitch is suspended for it and re-arms on the next
           WireGuard/OpenVPN/Happ connect.
"""

import contextlib
import ipaddress
import json
import re
import socket
import subprocess
import threading
import time
from pathlib import Path

import config
import fsutil
import logutil
from providers.base import ActionResult

SCRIPT = "/usr/local/bin/happ-killswitch"


def is_enabled() -> bool:
    """Probe through the script: unprivileged `nft list` needs CAP_NET_ADMIN
    and sudoers intentionally does not grant nft, so the NOPASSWD script's
    `is-on` subcommand is the only reliable source of truth."""
    result = subprocess.run(
        ["sudo", "-n", SCRIPT, "is-on"],
        capture_output=True,
        timeout=15,
        check=False,
    )
    return result.returncode == 0


STATE_CACHE = Path.home() / ".cache/vpn-manager/killswitch-state.json"
STATE_MAX_AGE = 30  # seconds; every change through _sudo() drops the cache


def cached_is_enabled() -> bool:
    """is_enabled() for the 3 s --status tick: the probe is a sudo
    subprocess, so its answer is kept for STATE_MAX_AGE. Anything that
    changes the rules goes through _sudo(), which deletes the cache —
    toggles show at once, only an outside change (`sudo happ-killswitch
    on` by hand) can lag by up to STATE_MAX_AGE."""
    try:
        state = json.loads(STATE_CACHE.read_text())
        if time.time() - state["at"] < STATE_MAX_AGE:
            return bool(state["on"])
    except OSError, ValueError, KeyError, TypeError:
        pass
    on = is_enabled()
    with contextlib.suppress(OSError):
        fsutil.write_json_atomic(STATE_CACHE, {"at": time.time(), "on": on})
    return on


def mode() -> str:
    return config.load_config().killswitch_mode


def enable(
    extra_ips: list[str] | None = None,
    ifaces: list[str] | None = None,
    fresh: bool = False,
    dns: list[str] | None = None,
) -> ActionResult:
    """Enable the killswitch, re-detecting Happ server IPs first (they
    change when the user switches servers).

    extra_ips / ifaces are the "all"-mode additions: resolved
    WireGuard/OpenVPN endpoint addresses and tunnel interface names.
    extra_ips=None means happ-only mode, where a failed detect is fatal;
    in "all" mode a failed detect is tolerated (Happ may simply be
    disconnected) and any stale conf IPs are merged in by the script.

    fresh=True means extra_ips are already the complete, known server set:
    skip `detect` (it scrapes every established TCP session on the physical
    NIC — split-tunnel "direct" sites included, while UDP transports like
    hysteria never show up) and tell the script not to merge the saved conf
    (whatever server was detected last time).

    dns: resolvers allowed on port 53 — only while a connect resolves its
    endpoints (system_resolvers()); without it DNS leaves only through the
    tunnel, the xray mark or the LAN.

    Every load also passes system_resolvers() as --happd-dns: port 53 to them
    for happd's cgroup only. xray (run by happd) resolves a hostname server
    with the system resolver, and that lookup leaves through its unmarked
    `direct` outbound — without this, hostname servers can't connect under
    the kill switch."""
    tail: list[str] = []
    for iface in ifaces or []:
        tail += ["--iface", iface]
    for server in dns or []:
        tail += ["--dns", server]
    for server in system_resolvers():
        tail += ["--happd-dns", server]
    if fresh:
        return _sudo("on", "--no-conf", *(extra_ips or []), *tail)
    detect = _sudo("detect")
    if not detect.success and extra_ips is None:
        return detect
    return _sudo("on", *(extra_ips or []), *tail)


def disable() -> ActionResult:
    return _sudo("off")


def redetect() -> ActionResult:
    """Refresh server IP whitelist without touching the on/off state."""
    return _sudo("detect")


# ── Mode-aware helpers used by the menu / connect guard ──────────────────────


def set_mode(
    on: bool,
    extra_ips: list[str] | None = None,
    ifaces: list[str] | None = None,
    apply: bool = True,
) -> ActionResult:
    """Menu toggle: persist the preference ("all" when on) and apply it.
    apply=False only saves it: with Lockdown off and no VPN up there is
    nothing to protect yet — the next connect puts the rules in place."""
    cfg = config.load_config()
    cfg.killswitch_mode = "all" if on else "off"
    config.save_config(cfg)
    if not on:
        return disable()
    if not apply:
        return ActionResult(
            True, "killswitch ON — rules apply with the next connect (Lockdown off)"
        )
    return enable(extra_ips, ifaces)


def suspend_for(provider_name: str) -> ActionResult:
    """Runtime-disable for a non-Happ provider; preference is kept."""
    result = disable()
    if result.success:
        result.message = (
            f"killswitch suspended for {provider_name} (auto-resumes on next Happ connect)"
        )
    return result


def resume_for_happ(
    extra_ips: list[str] | None = None, dns: list[str] | None = None
) -> ActionResult | None:
    """On Happ connect: refresh whitelist / re-enable if auto mode asks for it.

    extra_ips is the resolved address of the server being connected —
    detect() cannot see it yet (xray has no established session before the
    connect), so the caller passes it explicitly. Returns None when there
    is nothing to do."""
    if extra_ips is not None:
        # rebuild the rules around the known server addresses; a non-empty
        # list is the complete set, so skip detect/saved IPs (fresh)
        kwargs: dict = {"extra_ips": extra_ips, "dns": dns}
        if extra_ips:
            kwargs["fresh"] = True
        if is_enabled() or mode() in ("happ", "all"):
            return enable(**kwargs)
        return None
    if is_enabled():
        return redetect()
    if mode() in ("happ", "all"):
        return enable()
    return None


RESOLV_CONF = Path("/etc/resolv.conf")
_RESOLVECTL_ADDR = re.compile(r"(?<![\w:.])([0-9A-Fa-f:.]+)(?:%\S+)?(?:#\S+)?")


def system_resolvers() -> list[str]:
    """The resolvers the system sends DNS to — the connect-time exception
    in the kill switch (enable(dns=...)) opens port 53 to these only.

    resolv.conf's nameservers, unless it points at a local stub
    (systemd-resolved's 127.0.0.53): then its upstreams from `resolvectl
    dns` ("Link 3 (wlp5s0): 192.168.1.1", "Global: 1.1.1.1#cloudflare-dns.com")."""
    found: list[str] = []
    stub = False
    try:
        lines = RESOLV_CONF.read_text().splitlines()
    except OSError:
        lines = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            addr = _ip(parts[1].split("%")[0])
            if addr is None:
                continue
            if addr.is_loopback:
                stub = True
            else:
                found.append(str(addr))
    if stub:
        try:
            out = subprocess.run(
                ["resolvectl", "dns"], capture_output=True, text=True, timeout=5, check=False
            ).stdout
        except OSError, subprocess.SubprocessError:
            out = ""
        for line in out.splitlines():
            # a wrapped server list continues on an unlabelled, indented line
            servers = line if line[:1].isspace() else line.partition(":")[2]
            for token in servers.split():
                match = _RESOLVECTL_ADDR.fullmatch(token)
                addr = _ip(match.group(1)) if match else None
                if addr is not None and not addr.is_loopback:
                    found.append(str(addr))
    return list(dict.fromkeys(found))


def _ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


RESOLVE_TIMEOUT = 4.0  # seconds for all lookups together
RESOLVED_CACHE = Path.home() / ".cache/vpn-manager/resolved-ips.json"


def resolve_endpoint_ips(
    targets: list[tuple[str, str, int]],
    timeout: float = RESOLVE_TIMEOUT,
    cached_only: bool = False,
) -> list[str]:
    """IPv4 addresses for (name, host, port) targets, sorted, deduplicated.

    All hosts are looked up in parallel within `timeout`. A switch away from
    a dead server resolves through that dead tunnel (the system resolver's
    route goes into it): glibc then hung ~2 min per host, one after another,
    and held the switch for 15 minutes (2026-10-13). A host that doesn't
    answer in time falls back to its last known address (RESOLVED_CACHE), so
    the whitelist still has it; one never resolved is skipped with a log
    line — a dead endpoint must not abort the whole whitelist. IPv6 endpoints
    are skipped (the nft ruleset only has `ip daddr` v4 matches; a v6 literal
    would fail the whole ruleset load).

    Lookup threads are daemons: getaddrinfo can't be cancelled, and a stuck
    one must not hold the process open after the switch is done."""
    hosts: dict[str, str] = {}
    for name, host, _port in targets:
        hosts.setdefault(host, name)
    if cached_only:
        # no lookups: IP literals plus the last known addresses (opening the
        # connect-time DNS hole must not wait on DNS the old rules block)
        known = _read_resolved()
        found = {str(a) for h in hosts if (a := _ip(h)) is not None and a.version == 4}
        return sorted(found | {known[h] for h in hosts if h in known})
    answers: dict[str, str | OSError] = {}

    def lookup(host: str) -> None:
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET)
        except OSError as e:
            answers[host] = e
            return
        if infos:
            answers[host] = str(infos[0][4][0])

    threads = [threading.Thread(target=lookup, args=(h,), daemon=True) for h in hosts]
    for t in threads:
        t.start()
    deadline = time.monotonic() + timeout
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))
    answers = dict(answers)  # late answers from stuck threads don't count

    known = _read_resolved()
    ips: set[str] = set()
    fresh: dict[str, str] = {}
    for host, name in hosts.items():
        answer = answers.get(host)
        if isinstance(answer, str):
            ips.add(answer)
            if answer != host:
                fresh[host] = answer
            continue
        why = answer if isinstance(answer, OSError) else f"no answer in {timeout:g} s"
        if host in known:
            ips.add(known[host])
            logutil.log(f"killswitch: {host} ({name}): {why}; using last known {known[host]}")
        else:
            logutil.log(f"killswitch: cannot resolve {host} ({name}): {why}")
    if fresh:
        with contextlib.suppress(OSError):
            fsutil.write_json_atomic(RESOLVED_CACHE, {**known, **fresh})
    return sorted(ips)


def _read_resolved() -> dict[str, str]:
    try:
        data = json.loads(RESOLVED_CACHE.read_text())
    except OSError, ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}


def _sudo(*args: str) -> ActionResult:
    with contextlib.suppress(OSError):
        STATE_CACHE.unlink(missing_ok=True)  # the rules may change: re-probe next tick
    result = subprocess.run(
        ["sudo", "-n", SCRIPT, *args],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    output = (result.stdout + result.stderr).strip()
    logutil.log(f"killswitch: {' '.join(args)} -> rc={result.returncode}: {output[:200]}")
    # error context can sit above the last line — nft prints the offending
    # rule, then a caret-only line ("    ^^^^"); keep the last meaningful one
    meaningful = [line for line in output.splitlines() if line.strip(" ^\t")]
    if result.returncode != 0:
        hint = " — run: make install" if "password" in output.lower() else ""
        reason = meaningful[-1] if meaningful else "no output"
        return ActionResult(False, f"killswitch {' '.join(args)} failed{hint}: {reason}")
    message = meaningful[-1] if meaningful else f"killswitch {' '.join(args)}: ok"
    return ActionResult(True, message)
