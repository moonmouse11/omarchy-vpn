from providers import wireguard
from providers.wireguard import AmneziaWGProvider, WireGuardProvider


def _provider(tmp_path, monkeypatch, run_result=(0, "")):
    provider = WireGuardProvider()
    provider.config_dir = tmp_path / "dest"
    provider.config_dir.mkdir()
    monkeypatch.setattr(wireguard, "run_helper", lambda *a, **kw: run_result)
    return provider


def test_runtime_endpoint_parses_wg_show(monkeypatch):
    def fake_run(cmd):
        if cmd[:3] == ["wg", "show", "tun0"]:
            return 0, "peerkey\t45.140.17.3:4098\n"
        return 1, ""

    monkeypatch.setattr(wireguard, "_run", fake_run)
    monkeypatch.setattr(wireguard.shutil, "which", lambda b: "/usr/bin/wg" if b == "wg" else None)
    assert wireguard._runtime_endpoint("tun0", awg=False) == ("45.140.17.3", 4098)


def test_orphan_ping_target_uses_runtime_endpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(wireguard, "_active_interfaces", lambda *_: ["gone"])
    monkeypatch.setattr(
        wireguard,
        "_runtime_endpoint",
        lambda iface, awg: ("203.0.113.9", 51820) if iface == "gone" and awg else None,
    )
    awg = AmneziaWGProvider()
    awg.config_dir = tmp_path / "missing"
    awg.other_config_dirs = ()
    assert awg.ping_targets() == [("gone", "203.0.113.9", 51820, True)]


def test_awg_interface_names_empty_without_awg_binary(monkeypatch):
    monkeypatch.setattr(wireguard.shutil, "which", lambda b: None if b == "awg" else "/bin/sh")
    assert wireguard._awg_interface_names() == set()


def test_awg_interface_names_parses_awg_show(monkeypatch):
    monkeypatch.setattr(wireguard.shutil, "which", lambda b: "/usr/bin/awg" if b == "awg" else None)
    monkeypatch.setattr(
        wireguard,
        "_run",
        lambda cmd: (0, "tunnel-a\ntunnel-b\n\n") if cmd[:2] == ["awg", "show"] else (1, ""),
    )
    assert wireguard._awg_interface_names() == {"tunnel-a", "tunnel-b"}


def test_awg_interface_names_empty_on_awg_failure(monkeypatch):
    monkeypatch.setattr(wireguard.shutil, "which", lambda b: "/usr/bin/awg" if b == "awg" else None)
    monkeypatch.setattr(wireguard, "_run", lambda cmd: (1, "failed"))
    assert wireguard._awg_interface_names() == set()


def test_amnezia_connections_include_awg_show_orphans(tmp_path, monkeypatch):
    monkeypatch.setattr(wireguard, "_active_interfaces", lambda *_: [])
    monkeypatch.setattr(wireguard, "_awg_interface_names", lambda: {"gone"})
    awg = AmneziaWGProvider()
    awg.config_dir = tmp_path / "missing"
    awg.other_config_dirs = ()
    conns = awg.connections()
    assert len(conns) == 1
    assert conns[0].name == "gone"
    assert conns[0].active
    assert conns[0].config_path is None


def test_amnezia_skips_awg_show_when_kernel_lists_interfaces(tmp_path, monkeypatch):
    def kernel(lt):
        return ["home"] if lt == "amneziawg" else []

    monkeypatch.setattr(wireguard, "_active_interfaces", kernel)
    monkeypatch.setattr(
        wireguard,
        "_awg_interface_names",
        lambda: (_ for _ in ()).throw(AssertionError("awg show must not run")),
    )
    monkeypatch.setattr(wireguard, "_net_iface_exists", lambda n: False)
    awg = AmneziaWGProvider()
    awg.config_dir = tmp_path / "cfg"
    awg.config_dir.mkdir()
    (awg.config_dir / "home.conf").write_text("[Interface]\n")
    conns = awg.connections()
    assert any(c.name == "home" and c.active for c in conns)


def test_import_warns_when_dns_missing(tmp_path, monkeypatch):
    provider = _provider(tmp_path, monkeypatch)
    src = tmp_path / "nl.conf"
    src.write_text("[Interface]\nPrivateKey = x\n\n[Peer]\nEndpoint = 1.2.3.4:51820\n")

    result = provider.import_config(str(src))
    assert result.success
    assert "no DNS=" in result.message


def test_import_silent_when_dns_present(tmp_path, monkeypatch):
    provider = _provider(tmp_path, monkeypatch)
    src = tmp_path / "nl.conf"
    src.write_text(
        "[Interface]\nPrivateKey = x\nDNS = 10.0.0.1\n\n[Peer]\nEndpoint = 1.2.3.4:51820\n"
    )

    result = provider.import_config(str(src))
    assert result.success
    assert "no DNS=" not in result.message


def test_import_dns_key_lookup_is_case_insensitive(tmp_path, monkeypatch):
    provider = _provider(tmp_path, monkeypatch)
    src = tmp_path / "nl.conf"
    src.write_text("[Interface]\ndns = 10.0.0.1\n\n[Peer]\nEndpoint = 1.2.3.4:51820\n")

    result = provider.import_config(str(src))
    assert "no DNS=" not in result.message


def test_import_ignores_dns_looking_key_in_peer_section(tmp_path, monkeypatch):
    provider = _provider(tmp_path, monkeypatch)
    src = tmp_path / "nl.conf"
    # a DNS-looking key inside [Peer] must not count — only [Interface] does
    src.write_text(
        "[Interface]\nprivatekey = x\n\n[Peer]\nDns = 1.1.1.1\nEndpoint = 1.2.3.4:51820\n"
    )

    result = provider.import_config(str(src))
    assert "no DNS=" in result.message


def test_has_dns_directive_unreadable_file_treated_as_present(tmp_path):
    missing = tmp_path / "nope.conf"
    assert wireguard._has_dns_directive(missing) is True


def test_import_pipes_the_config_to_the_helper_by_name(tmp_path, monkeypatch):
    provider = _provider(tmp_path, monkeypatch)
    seen = []
    monkeypatch.setattr(
        wireguard, "run_helper", lambda *a, stdin=None, **kw: seen.append((a, stdin)) or (0, "")
    )
    src = tmp_path / "nl.conf"
    src.write_text("[Interface]\nDNS = 1.1.1.1\n")
    assert provider.import_config(str(src)).success
    assert seen == [(("import", "wg", "nl"), src.read_text())]


def test_amneziawg_uses_its_own_kind(tmp_path, monkeypatch):
    from providers.base import VPNConnection
    from providers.wireguard import AmneziaWGProvider

    calls = []
    monkeypatch.setattr(wireguard.shutil, "which", lambda b: "/usr/bin/awg-quick")
    monkeypatch.setattr(wireguard, "run_helper", lambda *a, **kw: calls.append(a) or (0, ""))
    AmneziaWGProvider().connect(VPNConnection(name="nl", provider="AmneziaWG", active=False))
    assert calls == [("up", "awg", "nl")]


def test_quick_connect_error_prefers_last_error_line():
    out = "[#] ip link add x\nError: IPv6 is disabled on nexthop device.\n"
    assert wireguard._quick_connect_error(out) == "Error: IPv6 is disabled on nexthop device."


def test_quick_connect_error_truncates_long_output_without_error_line():
    lines = [f"[#] step {i}" for i in range(200)]
    out = "\n".join(lines)
    msg = wireguard._quick_connect_error(out)
    assert msg.startswith("…")
    assert "step 199" in msg


def test_quick_connect_error_returns_plain_output_when_short():
    assert wireguard._quick_connect_error("boom") == "boom"


def test_wireguard_connect_without_wg_quick(monkeypatch):
    from providers.base import VPNConnection

    monkeypatch.setattr(wireguard.shutil, "which", lambda b: None)
    result = WireGuardProvider().connect(
        VPNConnection(name="nl", provider="WireGuard", active=False)
    )
    assert not result.success
    assert result.message == "wg-quick not found"


def test_connect_surfaces_helper_failure_via_quick_connect_error(tmp_path, monkeypatch):
    from providers.base import VPNConnection

    provider = _provider(
        tmp_path,
        monkeypatch,
        run_result=(2, "[#] up\nError: already exists\n"),
    )
    monkeypatch.setattr(wireguard.shutil, "which", lambda b: "/usr/bin/wg-quick")
    result = provider.connect(VPNConnection(name="nl", provider="WireGuard", active=False))
    assert not result.success
    assert result.message == "Error: already exists"


def test_amneziawg_connect_without_awg_quick(monkeypatch):
    from providers.base import VPNConnection
    from providers.wireguard import AWG_INSTALL_HINT, AmneziaWGProvider

    monkeypatch.setattr(wireguard.shutil, "which", lambda b: None)
    monkeypatch.setattr(
        wireguard,
        "run_helper",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("helper must not run")),
    )
    result = AmneziaWGProvider().connect(
        VPNConnection(name="nl", provider="AmneziaWG", active=False)
    )
    assert not result.success
    assert result.message == AWG_INSTALL_HINT


def test_delete_config_refuses_active_profile(tmp_path, monkeypatch):
    from providers.base import VPNConnection

    provider = _provider(tmp_path, monkeypatch)
    (provider.config_dir / "nl.conf").write_text("[Interface]\n")
    monkeypatch.setattr(
        wireguard,
        "run_helper",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("helper must not run")),
    )
    result = provider.delete_config(VPNConnection(name="nl", provider="WireGuard", active=True))
    assert not result.success
    assert "Disconnect" in result.message


def test_delete_disables_autostart_before_rm(tmp_path, monkeypatch):
    from providers.base import VPNConnection

    provider = _provider(tmp_path, monkeypatch)
    (provider.config_dir / "nl.conf").write_text("[Interface]\n")
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        wireguard,
        "run_helper",
        lambda *args: calls.append(args) or (0, ""),
    )
    monkeypatch.setattr(WireGuardProvider, "autostart_enabled", lambda self, n: True)
    result = provider.delete_config(VPNConnection(name="nl", provider="WireGuard", active=False))
    assert result.success
    assert calls == [("autostart", "wg", "nl", "off"), ("rm", "wg", "nl")]


def test_delete_config_not_found(tmp_path, monkeypatch):
    from providers.base import VPNConnection

    provider = _provider(tmp_path, monkeypatch)
    result = provider.delete_config(VPNConnection(name="nl", provider="WireGuard", active=False))
    assert not result.success
    assert "Config not found" in result.message


def test_delete_autostart_disable_failure(tmp_path, monkeypatch):
    from providers.base import VPNConnection

    provider = _provider(tmp_path, monkeypatch)
    (provider.config_dir / "nl.conf").write_text("[Interface]\n")

    def helper(*args):
        if args[0] == "autostart":
            return 1, "systemctl failed"
        return 0, ""

    monkeypatch.setattr(wireguard, "run_helper", helper)
    monkeypatch.setattr(WireGuardProvider, "autostart_enabled", lambda self, n: True)
    result = provider.delete_config(VPNConnection(name="nl", provider="WireGuard", active=False))
    assert not result.success
    assert "Failed to disable autostart" in result.message


def test_delete_rm_failure(tmp_path, monkeypatch):
    from providers.base import VPNConnection

    provider = _provider(tmp_path, monkeypatch)
    (provider.config_dir / "nl.conf").write_text("[Interface]\n")
    monkeypatch.setattr(wireguard, "run_helper", lambda *a: (1, "permission denied"))
    monkeypatch.setattr(WireGuardProvider, "autostart_enabled", lambda self, n: False)
    result = provider.delete_config(VPNConnection(name="nl", provider="WireGuard", active=False))
    assert not result.success
    assert "Failed to delete" in result.message


def test_amnezia_delete_disables_autostart_before_rm(tmp_path, monkeypatch):
    from providers.base import VPNConnection
    from providers.wireguard import AmneziaWGProvider

    provider = AmneziaWGProvider()
    monkeypatch.setattr(provider, "config_dir", tmp_path)
    (tmp_path / "nl.conf").write_text("[Interface]\n")
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        wireguard,
        "run_helper",
        lambda *args: calls.append(args) or (0, ""),
    )
    monkeypatch.setattr(AmneziaWGProvider, "autostart_enabled", lambda self, n: True)
    result = provider.delete_config(VPNConnection(name="nl", provider="AmneziaWG", active=False))
    assert result.success
    assert calls == [("autostart", "awg", "nl", "off"), ("rm", "awg", "nl")]
