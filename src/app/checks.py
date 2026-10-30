"""Tools checks (DNS leak, IP info, speed) and DNS autotest."""

import contextlib
import json
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import NoReturn

import config
import dnsleak
import fsutil
import ipinfo
import ipv6guard
import killswitch
import logutil
import notifyutil
import reputation
import speedtest
from app.helpers import notify, refresh_bar
from app.registry import active_connections
from app.switch import CheckCancelled
from happ.constants import MANAGER
from providers.base import (
    ActionResult,
    VPNConnection,
)


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


def _dns_verdict_path() -> Path:
    import vpn_manager as vm  # noqa: PLC0415 — tests patch vpn_manager.DNS_VERDICT_CACHE

    return vm.DNS_VERDICT_CACHE


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
        fsutil.write_json_atomic(_dns_verdict_path(), record)


def _read_dns_verdict(connection: str) -> dict | None:
    try:
        record = json.loads(_dns_verdict_path().read_text())
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
        [sys.executable, str(MANAGER), "--dns-autotest"],
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
    import vpn_manager as vm  # noqa: PLC0415 — tests patch vpn_manager._emit

    remote = getattr(vm, "_emit", None)
    if remote is not None and remote is not _emit:
        remote(obj)
        return
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
