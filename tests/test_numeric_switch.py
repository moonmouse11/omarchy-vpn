"""Numeric providers share bootstrap answers with nft without a second libc lookup."""

import pytest

import vpn_manager as vm
from app import switch
from providers.common.types import ActionResult, VPNConnection
from vpn_dns import snapshot


@pytest.fixture
def numeric_switch(monkeypatch, tmp_path):
    monkeypatch.setattr(vm.config, "CONFIG_PATH", tmp_path / "config.json")
    cfg = vm.config.load_config()
    cfg.killswitch_mode = "all"
    vm.config.save_config(cfg)
    connection = VPNConnection("office", "WireGuard", False)
    seen = []

    class Provider:
        name = "WireGuard"
        helper_kind = "wg"

        def connections(self):
            return [connection]

        def connect(self, conn):
            seen.append(dict(conn.endpoint_addresses or {}))
            return ActionResult(True, "connected")

    provider = Provider()
    monkeypatch.setattr(vm, "ALL_PROVIDERS", [provider])
    monkeypatch.setattr(vm.killswitch, "is_enabled", lambda: True)
    monkeypatch.setattr(vm.killswitch, "system_resolvers", lambda: ["192.0.2.53"])
    rules = []
    monkeypatch.setattr(
        vm.killswitch,
        "enable",
        lambda **kw: rules.append(kw) or ActionResult(True, "on"),
    )
    monkeypatch.setattr(vm, "_killswitch_all_targets", lambda **kw: ([], ["office"]))
    return provider, connection, seen, rules


def test_snapshot_reaches_native_and_exact_firewall_ips(numeric_switch, monkeypatch):
    provider, connection, seen, rules = numeric_switch
    monkeypatch.setattr(
        snapshot, "resolve_profile", lambda *args: ({"vpn.example": "192.0.2.1"}, ["192.0.2.1"])
    )

    def cached_only(**kwargs):
        assert kwargs["cached_only"], "numeric path must not make a second libc lookup"
        return [], ["office"]

    monkeypatch.setattr(vm, "_killswitch_all_targets", cached_only)
    assert switch._guarded_connect(provider, connection).success
    assert seen == [{"vpn.example": "192.0.2.1"}]
    assert any(rule["extra_ips"] == ["192.0.2.1"] for rule in rules)
    assert rules[-1]["extra_ips"] == ["192.0.2.1"]
    assert rules[-1]["dns"] == []
    assert all(rule.get("fresh") is True for rule in rules)
    assert connection.endpoint_addresses is None
    assert connection.endpoint_ipv4 is None


def test_incy_guard_snapshot_never_merges_detected_ips(monkeypatch):
    from types import SimpleNamespace

    seen = []
    monkeypatch.setattr(
        vm.killswitch, "enable", lambda **kw: seen.append(kw) or ActionResult(True, "ok")
    )
    switch._killswitch_apply(SimpleNamespace(name="INCY"), ["192.0.2.1"], ["incy-xray"], [])
    assert seen[0].get("fresh") is True


def test_failed_firewall_never_bootstraps_or_connects(numeric_switch, monkeypatch):
    provider, connection, seen, _ = numeric_switch
    monkeypatch.setattr(vm.killswitch, "enable", lambda **kw: ActionResult(False, "nft rejected"))
    monkeypatch.setattr(
        snapshot, "resolve_profile", lambda *a: pytest.fail("bootstrap before firewall")
    )
    result = switch._guarded_connect(provider, connection)
    assert not result.success
    assert "nft rejected" in result.message
    assert seen == []


def test_failed_bootstrap_never_connects_and_closes_dns(numeric_switch, monkeypatch):
    provider, connection, seen, rules = numeric_switch

    def fail(*args):
        raise OSError("no endpoint answer")

    monkeypatch.setattr(snapshot, "resolve_profile", fail)
    result = switch._guarded_connect(provider, connection)
    assert not result.success
    assert "no endpoint answer" in result.message
    assert seen == []
    assert rules[-1]["dns"] == []
    assert connection.endpoint_addresses is None
    assert connection.endpoint_ipv4 is None


@pytest.mark.parametrize("failure", ["bootstrap", "firewall", "cancel"])
@pytest.mark.parametrize("still_active", [False, True])
def test_failed_switch_reconciles_ipv6_but_cancellation_preserves_handover(
    numeric_switch, monkeypatch, failure, still_active
):
    provider, connection, seen, _ = numeric_switch
    cfg = vm.config.load_config()
    cfg.killswitch_lockdown = False
    vm.config.save_config(cfg)
    active = [VPNConnection("old", "Happ", True)]
    monkeypatch.setattr(switch, "active_connections", lambda **kw: active[:])
    state = {"ipv6_disabled": True, "reconciled": False}

    def guard(disabled):
        state.update(ipv6_disabled=disabled, reconciled=True)
        return ActionResult(True, "")

    monkeypatch.setattr(vm.ipv6guard, "enable", lambda: guard(False))
    monkeypatch.setattr(vm.ipv6guard, "disable", lambda: guard(True))
    monkeypatch.setattr(vm.killswitch, "disable", lambda: ActionResult(True, "off"))

    def disconnect(*, for_switch):
        assert for_switch
        if not still_active:
            active.clear()
        return ActionResult(True, "stopped")

    monkeypatch.setattr(vm, "_disconnect_all", disconnect)

    def resolve(*args):
        assert state["ipv6_disabled"], "IPv6 opened during teardown"
        if failure == "cancel":
            raise switch.SwitchCancelled
        if failure == "bootstrap":
            raise OSError("no endpoint answer")
        return {"vpn.example": "192.0.2.1"}, ["192.0.2.1"]

    monkeypatch.setattr(snapshot, "resolve_profile", resolve)
    monkeypatch.setattr(
        vm.killswitch,
        "enable",
        lambda **kw: ActionResult(kw.get("extra_ips") != ["192.0.2.1"], "nft rejected"),
    )
    if failure == "cancel":
        with pytest.raises(switch.SwitchCancelled):
            switch._guarded_connect(provider, connection)
        assert state == {"ipv6_disabled": True, "reconciled": False}
    else:
        assert not switch._guarded_connect(provider, connection).success
        assert state == {"ipv6_disabled": still_active, "reconciled": True}
    assert seen == []


def test_cancelled_bootstrap_closes_dns(numeric_switch, monkeypatch):
    provider, connection, seen, rules = numeric_switch

    class Cancelled(BaseException):
        pass

    def cancel(*args):
        raise Cancelled

    monkeypatch.setattr(snapshot, "resolve_profile", cancel)
    with pytest.raises(Cancelled):
        switch._guarded_connect(provider, connection)
    assert not seen
    assert rules[-1]["dns"] == []
    assert connection.endpoint_addresses is None
    assert connection.endpoint_ipv4 is None
