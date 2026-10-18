from providers import wireguard
from providers.wireguard import WireGuardProvider


def _provider(tmp_path, monkeypatch, run_result=(0, "")):
    provider = WireGuardProvider()
    provider.config_dir = tmp_path / "dest"
    provider.config_dir.mkdir()
    monkeypatch.setattr(wireguard, "run_helper", lambda *a, **kw: run_result)
    return provider


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
    monkeypatch.setattr(wireguard, "run_helper", lambda *a, **kw: calls.append(a) or (0, ""))
    AmneziaWGProvider().connect(VPNConnection(name="nl", provider="AmneziaWG", active=False))
    assert calls == [("up", "awg", "nl")]
