"""Killswitch integration for the VPN plugin.

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
import subprocess
import time
from dataclasses import replace
from pathlib import Path

import config
import fsutil
import logutil
from providers.base import ActionResult
from vpn_dns import resolvers as netresolvers

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

    dns: upstreams allowed only for dedicated marked bootstrap sockets on
    TCP/UDP :53. Never permits ordinary app/shared-resolved DNS or DoT.

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
    previous = config.load_config()
    cfg: config.Config = replace(previous, killswitch_mode="all" if on else "off")
    config.save_config_changes(previous, cfg)
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
        # Even an empty snapshot is complete: never scrape unrelated TCP sessions.
        kwargs: dict = {"extra_ips": extra_ips, "dns": dns, "fresh": True}
        if is_enabled() or mode() in ("happ", "all"):
            return enable(**kwargs)
        return None
    if is_enabled():
        return redetect()
    if mode() in ("happ", "all"):
        return enable()
    return None


RESOLV_CONF = Path("/etc/resolv.conf")


def system_resolvers() -> list[str]:
    """Numeric system upstreams; keep the facade path patchable for tests."""
    return netresolvers.system_resolvers(RESOLV_CONF)


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

    Dedicated marked/uplink-bound DNS sockets avoid libc and a dead current
    tunnel. The bootstrap client owns the global timeout and parallel queries.
    Missing answers fall back to last-known IPv4 values (RESOLVED_CACHE);
    never-resolved names and IPv6 literals are skipped, not guessed."""
    hosts: dict[str, str] = {}
    for name, host, _port in targets:
        hosts.setdefault(host, name)
    if cached_only:
        # No lookups before the marked bootstrap allowance has been installed.
        known = _read_resolved()
        found = {str(a) for h in hosts if (a := _ip(h)) is not None and a.version == 4}
        return sorted(found | {known[h] for h in hosts if h in known})
    from vpn_dns import bootstrap, wire  # noqa: PLC0415 — not part of periodic status imports

    literals = {h: str(a) for h in hosts if (a := _ip(h)) is not None and a.version == 4}
    names = []
    for host in hosts:
        if _ip(host) is not None:
            continue
        try:
            wire.canonical(host)
        except ValueError:
            logutil.log("killswitch: invalid endpoint hostname skipped")
        else:
            names.append(host)
    answers = dict(literals)
    try:
        if names:
            answers.update(bootstrap.resolve(names, timeout=timeout))
    except (OSError, ValueError) as error:
        logutil.log(f"killswitch: endpoint bootstrap unavailable: {error}")

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
        if (literal := _ip(host)) is not None and literal.version != 4:
            continue
        why = f"no bootstrap answer in {timeout:g} s"
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
