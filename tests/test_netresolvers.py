"""Root-safe system resolver discovery shares the facade's existing behavior."""

import importlib
import importlib.util
from types import SimpleNamespace

import pytest


def test_root_discovery_uses_fixed_resolvectl_binary(monkeypatch, tmp_path):
    assert importlib.util.find_spec("vpn_dns.resolvers") is not None
    mod = importlib.import_module("vpn_dns.resolvers")
    conf = tmp_path / "resolv.conf"
    conf.write_text("nameserver 127.0.0.53\n")
    calls = []
    monkeypatch.setattr(
        mod.subprocess,
        "run",
        lambda args, **kw: calls.append(args) or SimpleNamespace(stdout="Global: 1.1.1.1"),
    )
    assert mod.system_resolvers(conf) == ["1.1.1.1"]
    assert calls == [["/usr/bin/resolvectl", "dns"]]


def test_root_safe_discovery_has_no_application_dependency(tmp_path):
    assert importlib.util.find_spec("vpn_dns.resolvers") is not None
    mod = importlib.import_module("vpn_dns.resolvers")
    conf = tmp_path / "resolv.conf"
    conf.write_text("nameserver 1.1.1.1\nnameserver invalid\nnameserver 1.1.1.1\n")
    assert mod.system_resolvers(conf) == ["1.1.1.1"]


@pytest.mark.parametrize("mode", ["yes", "unknown", ""])
def test_bootstrap_never_downgrades_strict_or_unknown_tls(monkeypatch, tmp_path, mode):
    mod = importlib.import_module("vpn_dns.resolvers")
    conf = tmp_path / "resolv.conf"
    conf.write_text("nameserver 127.0.0.53\n")
    calls = []
    monkeypatch.setattr(
        mod.subprocess,
        "run",
        lambda args, **kw: (
            calls.append(args) or SimpleNamespace(stdout=f"Global: {mode}\n", returncode=0)
        ),
    )
    with pytest.raises(OSError):
        mod.bootstrap_resolvers(conf)
    assert calls == [["/usr/bin/resolvectl", "dnsovertls"]]


def test_bootstrap_does_not_substitute_resolved_for_a_local_proxy(tmp_path):
    mod = importlib.import_module("vpn_dns.resolvers")
    conf = tmp_path / "resolv.conf"
    conf.write_text("nameserver 127.0.0.1\n")
    with pytest.raises(OSError, match="proxy"):
        mod.bootstrap_resolvers(conf)


def test_bootstrap_permits_configured_plain_dns(monkeypatch, tmp_path):
    mod = importlib.import_module("vpn_dns.resolvers")
    conf = tmp_path / "resolv.conf"
    conf.write_text("nameserver 127.0.0.53\n")
    monkeypatch.setattr(
        mod.subprocess,
        "run",
        lambda args, **kw: SimpleNamespace(
            stdout="Global: no\n" if args[-1] == "dnsovertls" else "Global: 1.1.1.1\n",
            returncode=0,
        ),
    )
    assert mod.bootstrap_resolvers(conf) == ["1.1.1.1"]
