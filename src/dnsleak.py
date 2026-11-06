"""DNS leak test — same backend (bash.ws) as dnsleaktest.com and the
`dnsleaktest` CLI (https://github.com/macvk/dnsleaktest, MIT). Reimplemented
directly rather than shelling out to that script: a probe only needs to
trigger a DNS *lookup* of a unique subdomain, not a real ping (the ICMP
reply is discarded by the shell client too — only the lookup that reaches
bash.ws's authoritative nameserver matters), so a plain
socket.getaddrinfo() does the job with no external ping/curl/jq dependency.

Protocol: GET /id for a fresh test id, resolve {1..N}.{id}.bash.ws (whichever
resolver(s) your system actually uses for it), then GET
/dnsleak/test/{id}?json for what answered — entries tagged "ip" (your
public IP), "dns" (each detected resolver), "conclusion" (bash.ws's own
verdict text).
"""

import contextlib
import json
import re
import socket
import threading
import time
import urllib.error
from typing import TYPE_CHECKING

import lazyimports  # noqa: F401 — registers urllib.request & co. to load on first use

if TYPE_CHECKING:  # loaded lazily at run time, see lazyimports.py
    import urllib.request

API = "bash.ws"
PROBE_COUNT = 30
PROBE_TIMEOUT = 5  # seconds, bounds the whole probe wave regardless of stragglers
REQUEST_TIMEOUT = 8  # seconds, per HTTP call

STEPS = (
    f"requesting a test id from {API}",
    f"sending {PROBE_COUNT} DNS probes",
    f"fetching results from {API}",
)


class LeakTestError(Exception):
    """The test died at `step` (1-based index into STEPS) for `reason`."""

    def __init__(self, step: int, reason: str):
        self.step, self.reason = step, reason
        super().__init__(f"failed at {step}/{len(STEPS)} ({STEPS[step - 1]}): {reason}")


def _describe(e: Exception) -> str:
    """Short human reason: 'HTTP 503', 'The handshake operation timed out'."""
    if isinstance(e, urllib.error.HTTPError):
        return f"HTTP {e.code}"
    if isinstance(e, urllib.error.URLError):
        reason = e.reason
        text = str(reason) if not isinstance(reason, str) else reason
        return text.split(": ", 1)[-1] if text.startswith("_ssl.c") else text
    return str(e) or type(e).__name__


def _get_test_id() -> str:
    with urllib.request.urlopen(f"https://{API}/id", timeout=REQUEST_TIMEOUT) as resp:
        return resp.read().decode().strip()


def _probe(host: str) -> None:
    with contextlib.suppress(OSError):  # a failed lookup is fine — only the attempt matters
        socket.getaddrinfo(host, None)


def _send_probes(test_id: str) -> None:
    deadline = time.monotonic() + PROBE_TIMEOUT
    # libc lookups cannot be cancelled; daemon workers must not hold cancellation/process exit.
    workers = [
        threading.Thread(target=_probe, args=(f"{i}.{test_id}.{API}",), daemon=True)
        for i in range(1, PROBE_COUNT + 1)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=max(0, deadline - time.monotonic()))


def _fetch_results(test_id: str) -> list[dict]:
    url = f"https://{API}/dnsleak/test/{test_id}?json"
    with urllib.request.urlopen(url, timeout=REQUEST_TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def asn_number(asn: str | None) -> int | None:
    """13335 for bash.ws's 'AS13335 CloudFlare Inc', None if unparseable."""
    match = re.match(r"AS(\d+)", asn or "", re.IGNORECASE)
    return int(match.group(1)) if match else None


def server_tags(server: dict, ip_country: str, ip_asn: int | None) -> list[str]:
    """Mismatch indicators, not proof of the query's path. Network identity
    never suppresses a country mismatch; missing facts produce no indicator,
    but callers must not interpret that absence as a successful check."""
    asn = asn_number(server.get("asn"))
    tags = []
    if asn is not None and ip_asn is not None and asn != ip_asn:
        tags.append("ASN")
    country = (server.get("country") or "").upper()
    if country and ip_country and country != ip_country:
        tags.append("GEO")
    return tags


def run(on_step=None) -> dict:
    """{'ip', 'ip_country': 'DE'|'', 'ip_asn': 24940|None, 'dns_servers':
    [{'ip', 'country', 'country_name', 'asn', 'org'}], 'conclusion'} for a
    fresh test. ip_country is the 2-letter code bash.ws reports for the
    detected public IP itself (present in its "ip"-type entry, same shape as
    the "dns" entries) — kept separate from the bare ip string so the UI
    layer can render a flag without re-parsing the raw entry.

    on_step(n, label) is called before each of STEPS (progress). Raises
    LeakTestError(step, reason) instead of returning nothing: "Test failed
    — no network?" with no step or cause was undiagnosable (a slow exit
    timing out bash.ws's TLS handshake looked like no network at all)."""
    report = on_step or (lambda n, label: None)
    report(1, STEPS[0])
    try:
        test_id = _get_test_id()
    except (OSError, ValueError) as e:
        raise LeakTestError(1, _describe(e)) from e
    if not test_id:
        raise LeakTestError(1, f"{API} returned no test id")
    report(2, STEPS[1])
    _send_probes(test_id)  # failed lookups are fine — only the attempt matters
    report(3, STEPS[2])
    try:
        entries = _fetch_results(test_id)
    except (OSError, ValueError) as e:
        raise LeakTestError(3, _describe(e)) from e

    if not isinstance(entries, list):
        raise LeakTestError(3, f"unexpected response from {API}")
    ip_entry = next((e for e in entries if e.get("type") == "ip"), None)
    dns_servers = [e for e in entries if e.get("type") == "dns"]
    conclusion = next((e.get("ip") for e in entries if e.get("type") == "conclusion"), "")
    return {
        "ip": ip_entry.get("ip") if ip_entry else None,
        "ip_country": ((ip_entry or {}).get("country") or "").upper(),
        "ip_asn": asn_number((ip_entry or {}).get("asn")),
        "dns_servers": dns_servers,
        "conclusion": conclusion or "",
    }
