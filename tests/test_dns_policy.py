"""DNS identities and heuristics must not manufacture proof of a private path."""

import json

import pytest

import fsutil
import vpn_manager as vm
from app.checks import _read_dns_verdict
from providers.base import VPNConnection


@pytest.mark.parametrize(
    "country,asn,server",
    [
        ("DE", None, {"country": "DE", "asn": "AS13335"}),
        ("", 13335, {"country": "DE", "asn": "AS13335"}),
        ("DE", 13335, {"ip": "1.1.1.1"}),
        ("DE", 13335, {"country": "DE"}),
    ],
)
def test_sparse_metadata_cannot_earn_an_all_clear(country, asn, server):
    assert (
        vm._dns_leak_verdict_row({"ip_country": country, "ip_asn": asn, "dns_servers": [server]})
        is None
    )


@pytest.mark.parametrize(
    "address,name",
    [
        ("1.1.1.1", "Cloudflare"),
        ("8.8.8.8", "Google Public DNS"),
        ("94.140.14.14", "AdGuard DNS"),
        ("9.9.9.9", "Quad9"),
        ("208.67.222.222", "OpenDNS"),
        ("185.228.168.9", "CleanBrowsing"),
        ("76.76.2.0", "Control D"),
        ("84.200.69.80", "DNS.WATCH"),
        ("198.51.100.40", None),
    ],
)
def test_verified_dns_endpoint_names_are_metadata_only(address, name):
    from vpn_dns.identity import resolver_name

    assert resolver_name(address) == name
    assert vm.dnsleak.server_tags(
        {"ip": address, "country": "RU", "asn": "AS13335"}, "DE", 24940
    ) == ["ASN", "GEO"]


@pytest.mark.parametrize("at", ["invalid", None, float("nan"), float("inf")])
def test_malformed_dns_timestamp_cannot_earn_protected(at):
    conn = VPNConnection("server", "Happ", True)
    vm._save_dns_verdict([conn], "DNS test: no resolver mismatch detected")
    record = json.loads(vm.DNS_VERDICT_CACHE.read_text())
    record["at"] = at
    fsutil.write_json_atomic(vm.DNS_VERDICT_CACHE, record)
    assert _read_dns_verdict(conn.name) is None


def test_unrecognised_summary_cannot_become_a_clean_verdict():
    conn = VPNConnection("server", "Happ", True)
    vm._save_dns_verdict([conn], "DNS via VPN or public resolvers")
    assert _read_dns_verdict(conn.name)["leaked"] is None


def test_old_policy_cache_is_not_reused():
    conn = VPNConnection("server", "Happ", True)
    vm._save_dns_verdict([conn], "DNS via VPN or public resolvers")
    record = json.loads(vm.DNS_VERDICT_CACHE.read_text())
    record.pop("version", None)
    fsutil.write_json_atomic(vm.DNS_VERDICT_CACHE, record)
    assert _read_dns_verdict(conn.name) is None
