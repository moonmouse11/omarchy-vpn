"""A profile gets one IPv4 answer set, reused for runtime endpoints and nft."""

import importlib
import json

import pytest


def snapshot():
    return importlib.import_module("vpn_dns.snapshot")


def metadata(monkeypatch, data):
    mod = snapshot()
    calls = []
    monkeypatch.setattr(
        mod.helper, "run_helper", lambda *args: calls.append(args) or (0, json.dumps(data))
    )
    return mod, calls


def test_snapshot_reuses_exact_answers_for_runtime_and_whitelist(monkeypatch):
    mod, calls = metadata(
        monkeypatch,
        {"hosts": ["vpn.example"], "ipv4": ["192.0.2.9"], "random_hostname": False},
    )
    queries = []
    monkeypatch.setattr(
        mod.bootstrap,
        "resolve",
        lambda hosts: queries.append(hosts) or {"vpn.example": "192.0.2.1"},
    )
    mapping, ips = mod.resolve_profile("wg", "office")
    assert calls == [("profile-info", "wg", "office")]
    assert queries == [["vpn.example"]]
    assert mapping == {"vpn.example": "192.0.2.1"}
    assert ips == ["192.0.2.1", "192.0.2.9"]


def test_random_hostname_is_only_applied_to_bootstrap_query(monkeypatch):
    mod, _ = metadata(monkeypatch, {"hosts": ["vpn.example"], "ipv4": [], "random_hostname": True})
    monkeypatch.setattr(mod.secrets, "token_hex", lambda size: "aabbcc")
    queries = []
    monkeypatch.setattr(
        mod.bootstrap,
        "resolve",
        lambda hosts: queries.append(hosts) or {"aabbcc.vpn.example": "192.0.2.2"},
    )
    assert mod.resolve_profile("ovpn", "office") == ({"vpn.example": "192.0.2.2"}, ["192.0.2.2"])
    assert queries == [["aabbcc.vpn.example"]]


def test_literal_profile_never_starts_dns(monkeypatch):
    mod, _ = metadata(monkeypatch, {"hosts": [], "ipv4": ["192.0.2.8"], "random_hostname": False})
    monkeypatch.setattr(mod.bootstrap, "resolve", lambda hosts: pytest.fail("unexpected DNS"))
    assert mod.resolve_profile("awg", "office") == ({}, ["192.0.2.8"])


def test_unresolved_endpoint_aborts_instead_of_using_libc(monkeypatch):
    mod, _ = metadata(monkeypatch, {"hosts": ["vpn.example"], "ipv4": [], "random_hostname": False})
    monkeypatch.setattr(mod.bootstrap, "resolve", lambda hosts: {})
    with pytest.raises(OSError, match=r"vpn\.example"):
        mod.resolve_profile("wg", "office")


@pytest.mark.parametrize(
    "data",
    [
        [],
        {},
        {"hosts": "vpn.example", "ipv4": [], "random_hostname": False},
        {"hosts": [], "ipv4": [True], "random_hostname": False},
        {"hosts": [], "ipv4": ["::1"], "random_hostname": False},
        {"hosts": [], "ipv4": [], "random_hostname": "yes"},
    ],
)
def test_bad_profile_metadata_fails_closed(monkeypatch, data):
    mod, _ = metadata(monkeypatch, data)
    with pytest.raises(ValueError):
        mod.resolve_profile("wg", "office")
