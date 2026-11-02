"""Route observations are local diagnostics, not proof an app emitted a query."""

import json
import time
from types import SimpleNamespace

import pytest

import fsutil
from providers.base import VPNConnection
from vpn_dns import routes as dnsroutes


@pytest.fixture
def routes(monkeypatch, tmp_path):
    monkeypatch.setattr(dnsroutes, "CACHE", tmp_path / "dns-route.json")
    monkeypatch.setattr(
        dnsroutes.killswitch, "system_resolvers", lambda: ["192.168.1.1", "10.0.0.53"]
    )
    monkeypatch.setattr(
        dnsroutes.subprocess,
        "run",
        lambda cmd, **kw: SimpleNamespace(
            returncode=0,
            stdout=json.dumps([{"dev": "wg0" if cmd[-1] == "10.0.0.53" else "wlan0"}]),
        ),
    )
    return [VPNConnection("office", "WireGuard", True, interface="wg0")]


def test_only_private_dns_routed_outside_tunnel_is_a_lan_warning(routes):
    dnsroutes.update(routes)
    data = dnsroutes.read_cache()
    assert data["lan"] == [{"ip": "192.168.1.1", "interface": "wlan0"}]
    assert data["unknown"] == []
    hint = dnsroutes.warning("wg0")
    assert "192.168.1.1" in hint
    assert "does not prove" in hint
    assert "10.0.0.53" not in hint


def test_unknown_route_does_not_claim_router_or_private_path(routes, monkeypatch):
    monkeypatch.setattr(
        dnsroutes.subprocess, "run", lambda *a, **kw: SimpleNamespace(stdout="bad", returncode=1)
    )
    dnsroutes.update(routes)
    assert dnsroutes.read_cache()["lan"] == []
    assert dnsroutes.read_cache()["unknown"] == ["192.168.1.1", "10.0.0.53"]
    assert "unverified" in dnsroutes.warning("wg0")


def test_fresh_status_warning_reads_cache_without_running_commands(routes, monkeypatch):
    dnsroutes.update(routes)
    monkeypatch.setattr(
        dnsroutes.subprocess, "run", lambda *a, **kw: pytest.fail("status ran a command")
    )
    assert "192.168.1.1" in dnsroutes.warning("wg0")


@pytest.mark.parametrize("field,value", [("lan", [None]), ("unknown", [{}]), ("interfaces", [1])])
def test_malformed_cache_is_not_used_for_status(routes, field, value):
    data = {"at": time.time(), "interfaces": ["wg0"], "lan": [], "unknown": []}
    data[field] = value
    fsutil.write_json_atomic(dnsroutes.CACHE, data)
    assert dnsroutes.read_cache() is None


@pytest.mark.parametrize("case", ["stale", "wrong-tunnel"])
def test_stale_or_wrong_tunnel_observation_is_unknown_and_requests_refresh(
    routes, monkeypatch, case
):
    dnsroutes.update(routes)
    if case == "stale":
        data = dnsroutes.read_cache()
        data["at"] -= dnsroutes.MAX_AGE + 1
        fsutil.write_json_atomic(dnsroutes.CACHE, data)
    interface = "other-tunnel" if case == "wrong-tunnel" else "wg0"
    calls = []
    monkeypatch.setattr(dnsroutes, "spawn_manager", lambda *args: calls.append(args))
    assert "unverified" in dnsroutes.warning(interface)
    dnsroutes.warning(interface)
    assert calls == [("--dns-route-update",)]
