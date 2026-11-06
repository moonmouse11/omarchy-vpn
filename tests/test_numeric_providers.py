"""Providers pass the selected address map on stdin, including an empty literal map."""

import json

import pytest

from providers import openvpn, wireguard
from providers.common.types import VPNConnection


@pytest.mark.parametrize(
    ("cls", "shim", "kind"),
    [
        (wireguard.WireGuardProvider, wireguard, "wg"),
        (wireguard.AmneziaWGProvider, wireguard, "awg"),
        (openvpn.OpenVPNProvider, openvpn, "ovpn"),
    ],
)
@pytest.mark.parametrize("mapping", [{}, {"vpn.example": "192.0.2.1"}])
def test_provider_uses_numeric_helper_for_supplied_snapshot(monkeypatch, cls, shim, kind, mapping):
    monkeypatch.setattr(wireguard.shutil, "which", lambda name: "/usr/bin/" + name)
    calls = []
    monkeypatch.setattr(shim, "run_helper", lambda *a, **kw: calls.append((a, kw)) or (0, ""))
    provider = cls()
    ips = ["192.0.2.1"] if mapping else ["192.0.2.9"]
    connection = VPNConnection(
        "office", provider.name, False, endpoint_addresses=mapping, endpoint_ipv4=ips
    )
    assert provider.connect(connection).success
    assert calls == [
        (("up-numeric", kind, "office"), {"stdin": json.dumps({"addresses": mapping, "ipv4": ips})})
    ]
