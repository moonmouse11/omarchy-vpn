from providers.common import interfaceclaims


def _net(tmp_path, *names):
    root = tmp_path / "net"
    root.mkdir()
    for ifindex, name in enumerate(names, 1):
        interface = root / name
        interface.mkdir()
        (interface / "ifindex").write_text(str(ifindex))
    return root


def test_claim_get_release_and_other_provider_lookup(tmp_path, monkeypatch):
    monkeypatch.setattr(interfaceclaims, "CLAIM_FILE", tmp_path / "claims.json")
    monkeypatch.setattr(interfaceclaims, "SYS_NET", _net(tmp_path, "utun420", "tun0"))

    interfaceclaims.claim("Windscribe", "utun420")
    interfaceclaims.claim("OpenVPN", "tun0")

    assert interfaceclaims.get("Windscribe") == "utun420"
    assert interfaceclaims.claimed_by_others("WireGuard") == {"utun420", "tun0"}
    assert interfaceclaims.claimed_by_others("Windscribe") == {"tun0"}

    interfaceclaims.release("Windscribe")
    assert interfaceclaims.get("Windscribe") is None
    assert interfaceclaims.claimed_by_others("WireGuard") == {"tun0"}


def test_stale_missing_interface_is_ignored(tmp_path, monkeypatch):
    monkeypatch.setattr(interfaceclaims, "CLAIM_FILE", tmp_path / "claims.json")
    monkeypatch.setattr(interfaceclaims, "SYS_NET", _net(tmp_path, "utun420"))
    interfaceclaims.claim("Windscribe", "utun420")
    (interfaceclaims.SYS_NET / "utun420" / "ifindex").unlink()
    (interfaceclaims.SYS_NET / "utun420").rmdir()
    assert interfaceclaims.get("Windscribe") is None
    assert interfaceclaims.claimed_by_others("WireGuard") == set()


def test_recreated_interface_with_same_name_does_not_revive_stale_claim(tmp_path, monkeypatch):
    monkeypatch.setattr(interfaceclaims, "CLAIM_FILE", tmp_path / "claims.json")
    monkeypatch.setattr(interfaceclaims, "SYS_NET", _net(tmp_path, "utun420"))
    interfaceclaims.claim("Windscribe", "utun420")
    (interfaceclaims.SYS_NET / "utun420" / "ifindex").write_text("99")
    assert interfaceclaims.get("Windscribe") is None
    assert interfaceclaims.claimed_by_others("WireGuard") == set()


def test_claim_from_previous_boot_is_ignored(tmp_path, monkeypatch):
    boot_id = tmp_path / "boot-id"
    boot_id.write_text("boot-a")
    monkeypatch.setattr(interfaceclaims, "CLAIM_FILE", tmp_path / "claims.json")
    monkeypatch.setattr(interfaceclaims, "SYS_NET", _net(tmp_path, "utun420"))
    monkeypatch.setattr(interfaceclaims, "BOOT_ID_FILE", boot_id)
    interfaceclaims.claim("Windscribe", "utun420")
    boot_id.write_text("boot-b")
    assert interfaceclaims.get("Windscribe") is None
    assert interfaceclaims.claimed_by_others("WireGuard") == set()


def test_path_like_interface_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(interfaceclaims, "CLAIM_FILE", tmp_path / "claims.json")
    monkeypatch.setattr(interfaceclaims, "SYS_NET", _net(tmp_path, "utun420"))
    interfaceclaims.claim("Windscribe", "../utun420")
    assert interfaceclaims.get("Windscribe") is None
    assert not interfaceclaims.CLAIM_FILE.exists()
