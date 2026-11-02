"""Numeric runtime profiles preserve user settings and native SaveConfig behavior."""

import importlib
import importlib.util

import pytest

WG = """[Interface]
PrivateKey = private
Address = 10.0.0.2/32
DNS = 10.0.0.53
SaveConfig = true
PostUp = echo trusted-root-hook
[Peer]
PublicKey = first
Endpoint = vpn.example:51820
AllowedIPs = 0.0.0.0/0
[Peer]
PublicKey = second
Endpoint = 192.0.2.2:51821
"""


def profiles():
    assert importlib.util.find_spec("dnsprofiles") is not None, (
        "runtime profile preparation is missing"
    )
    return importlib.import_module("dnsprofiles")


def test_runtime_replaces_only_hostname_endpoints():
    mod = profiles()
    runtime = mod.numeric_config("wg", WG, {"vpn.example": "192.0.2.1"})
    assert runtime == WG.replace("vpn.example:51820", "192.0.2.1:51820")
    assert "DNS = 10.0.0.53" in runtime
    assert "SaveConfig = true" in runtime
    assert "PostUp = echo trusted-root-hook" in runtime


@pytest.mark.parametrize(
    "mapping",
    [
        {},
        {"extra.example": "192.0.2.1"},
        {"vpn.example": "invalid"},
        {"vpn.example": "::1"},
        {"vpn.example": "1.2.3.4\nPostUp = bad"},
        {"vpn.example": 16909060},
        {"vpn.example": True},
    ],
)
def test_missing_extra_or_non_ipv4_overrides_are_refused(mapping):
    mod = profiles()
    with pytest.raises(ValueError):
        mod.numeric_config("wg", WG, mapping)


def test_hostname_peer_without_public_key_is_rejected_before_runtime_copy():
    mod = profiles()
    text = "[Peer]\nEndpoint = vpn.example:51820\n"
    with pytest.raises(ValueError, match="PublicKey"):
        mod.numeric_config("wg", text, {"vpn.example": "192.0.2.1"})


def test_wireguard_endpoint_whitespace_and_late_public_key_are_preserved():
    mod = profiles()
    text = "[Peer]\nEndpoint = vpn.example : 51820 # endpoint\nPublicKey = first\n"
    runtime = mod.numeric_config("wg", text, {"vpn.example": "192.0.2.1"})
    assert "Endpoint = 192.0.2.1 : 51820 # endpoint" in runtime
    assert mod.restore_hostnames(runtime, text) == text


def test_wireguard_native_whitespace_normalization_does_not_lose_host_or_peer():
    mod = profiles()
    text = "[Pe er]\nEnd point = v p n . example : 51820\nPublic Key = f i r s t\n"
    runtime = mod.numeric_config("wg", text, {"vpn.example": "192.0.2.1"})
    assert "192.0.2.1 : 51820" in runtime
    saved = "[Peer]\nPublicKey = first\nEndpoint = 192.0.2.1:51820\n"
    assert "Endpoint = vpn.example:51820" in mod.restore_hostnames(saved, text)


def test_saveconfig_restores_hostnames_by_public_key_and_keeps_state_updates():
    mod = profiles()
    runtime = mod.numeric_config("awg", WG, {"vpn.example": "192.0.2.1"})
    saved = runtime.replace("10.0.0.2/32", "10.0.0.7/32").replace(
        "192.0.2.1:51820", "192.0.2.1:9999"
    )
    saved += "[Peer]\nPublicKey = new-peer\nEndpoint = 192.0.2.9:2345\n"
    restored = mod.restore_hostnames(saved, WG)
    assert "Endpoint = vpn.example:9999" in restored
    assert "Address = 10.0.0.7/32" in restored
    assert "Endpoint = 192.0.2.9:2345" in restored
    assert "Endpoint = 192.0.2.2:51821" in restored


def test_openvpn_multiple_remotes_blocks_and_random_hostname_are_numeric():
    mod = profiles()
    original = (
        'client\nremote-random-hostname\nremote "one.example" 1194 udp # keep\n'
        "<connection>\nremote two.example 443 tcp\n</connection>\n"
        "<key>\nremote private-key-data\n</key>\ndhcp-option DNS 10.0.0.53\n"
    )
    runtime = mod.numeric_config(
        "ovpn", original, {"one.example": "192.0.2.1", "two.example": "192.0.2.2"}
    )
    assert "remote 192.0.2.1 1194 udp # keep" in runtime
    assert "remote 192.0.2.2 443 tcp" in runtime
    assert "remote-random-hostname" not in runtime
    assert "remote private-key-data" in runtime
    assert "dhcp-option DNS 10.0.0.53" in runtime
    assert original.startswith("client\nremote-random-hostname\n")
