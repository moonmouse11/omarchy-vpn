"""Root-safe system resolver discovery shares the facade's existing behavior."""

import importlib
import importlib.util
from types import SimpleNamespace


def test_root_discovery_uses_fixed_resolvectl_binary(monkeypatch, tmp_path):
    assert importlib.util.find_spec("netresolvers") is not None
    mod = importlib.import_module("netresolvers")
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
    assert importlib.util.find_spec("netresolvers") is not None
    mod = importlib.import_module("netresolvers")
    conf = tmp_path / "resolv.conf"
    conf.write_text("nameserver 1.1.1.1\nnameserver invalid\nnameserver 1.1.1.1\n")
    assert mod.system_resolvers(conf) == ["1.1.1.1"]
