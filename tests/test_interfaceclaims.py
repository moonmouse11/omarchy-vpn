from providers.common import interfaceclaims


def _net(tmp_path, *names):
    root = tmp_path / "net"
    root.mkdir()
    for name in names:
        (root / name).mkdir()
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
    (interfaceclaims.SYS_NET / "utun420").rmdir()
    assert interfaceclaims.get("Windscribe") is None
    assert interfaceclaims.claimed_by_others("WireGuard") == set()


def test_path_like_interface_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(interfaceclaims, "CLAIM_FILE", tmp_path / "claims.json")
    monkeypatch.setattr(interfaceclaims, "SYS_NET", _net(tmp_path, "utun420"))
    interfaceclaims.claim("Windscribe", "../utun420")
    assert interfaceclaims.get("Windscribe") is None
    assert not interfaceclaims.CLAIM_FILE.exists()
