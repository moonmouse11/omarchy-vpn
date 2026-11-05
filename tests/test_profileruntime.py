"""Root-owned runtime copies never replace user's DNS/settings with bootstrap state."""

import importlib
import importlib.util
import stat
from io import StringIO

import pytest
from test_dnsprofiles import WG


def runtime():
    assert importlib.util.find_spec("vpn_dns.runtime") is not None, (
        "private runtime storage is missing"
    )
    return importlib.import_module("vpn_dns.runtime")


def test_private_profile_runtime_is_available():
    runtime()


def test_prepare_rejects_changed_literal_endpoint_before_native_start(files):
    mod, source = files
    source.write_text(WG.replace("192.0.2.2", "192.0.2.3"))
    with pytest.raises(ValueError, match="changed"):
        mod.prepare(
            "wg",
            "office",
            {"vpn.example": "192.0.2.1"},
            expected_ips=["192.0.2.1", "192.0.2.2"],
        )
    assert "192.0.2.3" in source.read_text()
    assert not mod.RUNTIME.exists()


def test_literal_profile_is_also_private_for_failed_up_cleanup(files):
    mod, source = files
    original = WG.replace("vpn.example", "192.0.2.1")
    source.write_text(original)
    path = mod.prepare("wg", "office", {})
    assert path != source
    path.write_text("partial native state")
    mod.finish("wg", "office", save=False)
    assert source.read_text() == original


def test_cancelled_start_cannot_save_partial_state(files):
    mod, source = files
    path = mod.prepare("wg", "office", {"vpn.example": "192.0.2.1"})
    mod.mark("wg", "office", "starting")
    path.write_text("partial native state")
    mod.mark("wg", "office", "stopping")
    mod.finish("wg", "office", save=True)
    assert source.read_text() == WG


def test_recover_prepared_profile_does_not_overwrite_external_edit(files):
    mod, source = files
    mod.prepare("wg", "office", {"vpn.example": "192.0.2.1"})
    source.write_text(WG + "# user's newer setting\n")
    mod.recover("wg", "office")
    assert source.read_text().endswith("# user's newer setting\n")


def test_recover_interrupted_native_save_keeps_its_changes(files):
    mod, source = files
    path = mod.prepare("wg", "office", {"vpn.example": "192.0.2.1"})
    mod.mark("wg", "office", "starting")
    mod.mark("wg", "office", "started")
    mod.mark("wg", "office", "stopping")
    path.write_text(path.read_text().replace("51820", "51821"))
    mod.recover("wg", "office")
    assert "vpn.example:51821" in source.read_text()
    assert not path.parent.exists()


@pytest.mark.parametrize("kind", ["wg", "awg"])
@pytest.mark.parametrize("replacement", ["edit", "reimport"])
def test_failed_save_recovery_refuses_replacement_credentials(
    files, monkeypatch, kind, replacement
):
    mod, source = files
    path = mod.prepare(kind, "office", {"vpn.example": "192.0.2.1"})
    mod.mark(kind, "office", "stopping")
    path.write_text(path.read_text().replace("51820", "51822"))
    with monkeypatch.context() as patch:
        patch.setattr(mod, "_atomic_text", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
        with pytest.raises(OSError, match="disk full"):
            mod.finish(kind, "office", save=True)
    if replacement == "reimport":
        source.unlink()
    newer = WG.replace("PrivateKey = private", "PrivateKey = replacement")
    source.write_text(newer)
    with pytest.raises(ValueError, match="changed"):
        mod.recover(kind, "office")
    assert source.read_text() == newer
    assert path.exists()
    assert (path.parent / ".saving").exists()
    assert "51822" in path.read_text()


def test_recovery_accepts_already_applied_save_after_retirement_failure(files, monkeypatch):
    mod, source = files
    path = mod.prepare("wg", "office", {"vpn.example": "192.0.2.1"})
    mod.mark("wg", "office", "stopping")
    path.write_text(path.read_text().replace("51820", "51822"))
    with monkeypatch.context() as patch:
        patch.setattr(mod, "_retire", lambda *a: (_ for _ in ()).throw(OSError("rename failed")))
        with pytest.raises(OSError, match="rename failed"):
            mod.finish("wg", "office", save=True)
    assert "vpn.example:51822" in source.read_text()
    assert mod.recover("wg", "office")
    assert "vpn.example:51822" in source.read_text()
    assert not path.parent.exists()


def test_profile_metadata_never_exports_secrets(files):
    mod, source = files
    source.write_text(WG + "\n[Peer]\nPublicKey = second\nEndpoint = 192.0.2.9:51820\n")
    assert mod.describe("wg", "office") == {
        "hosts": ["vpn.example"],
        "ipv4": ["192.0.2.2", "192.0.2.9"],
        "random_hostname": False,
    }


def test_openvpn_quoted_remote_is_rejected_before_runtime_creation(files):
    mod, source = files
    source.write_text('client\n"remote" vpn.example 1194\n')
    with pytest.raises(ValueError, match="directive syntax"):
        mod.prepare("ovpn", "office", {}, expected_ips=[])
    assert not mod.RUNTIME.exists()
    assert source.read_text() == 'client\n"remote" vpn.example 1194\n'


def test_openvpn_metadata_skips_inline_secrets(files):
    mod, source = files
    source.write_text(
        "client\nremote VPN.Example 1194\nremote-random-hostname\n"
        "<key>\nremote secret.example 1234\n</key>\n"
        "<connection>\nremote 192.0.2.8 443\n</connection>\n"
    )
    assert mod.describe("ovpn", "office") == {
        "hosts": ["vpn.example"],
        "ipv4": ["192.0.2.8"],
        "random_hostname": True,
    }


@pytest.fixture
def files(monkeypatch, tmp_path):
    mod = runtime()
    config = tmp_path / "configs"
    config.mkdir(mode=0o700)
    source = config / "office.conf"
    source.write_text(WG)
    source.chmod(0o640)
    monkeypatch.setattr(mod, "DIRECTORIES", {"wg": config, "awg": config, "ovpn": config})
    monkeypatch.setattr(mod, "RUNTIME", tmp_path / "runtime")
    return mod, source


def test_cli_prepare_current_and_finish_preserve_source_settings(files, monkeypatch, capsys):
    mod, source = files
    monkeypatch.setattr(
        mod.sys,
        "stdin",
        StringIO('{"addresses":{"vpn.example":"192.0.2.1"},"ipv4":["192.0.2.1","192.0.2.2"]}'),
    )
    assert mod.main(["prepare", "wg", "office"]) == 0
    path = capsys.readouterr().out.strip()
    assert path.endswith("/wg-office/office.conf")
    assert mod.main(["current", "wg", "office"]) == 0
    assert capsys.readouterr().out.strip() == path
    assert mod.main(["finish", "wg", "office"]) == 0
    assert source.read_text() == WG


@pytest.mark.parametrize("data", ["not-json", "[]", '{"vpn.example":1234}'])
def test_cli_bad_maps_fail_without_source_write(files, monkeypatch, capsys, data):
    mod, source = files
    monkeypatch.setattr(mod.sys, "stdin", StringIO(data))
    assert mod.main(["prepare", "wg", "office"]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert "private" not in output.err
    assert source.read_text() == WG


def test_prepare_preserves_source_and_uses_private_same_basename(files):
    mod, source = files
    path = mod.prepare("wg", "office", {"vpn.example": "192.0.2.1"})
    assert source.read_text() == WG
    assert path.name == source.name
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert "Endpoint = 192.0.2.1:51820" in path.read_text()


@pytest.mark.parametrize("kind", ["wg", "awg"])
def test_finish_preserves_saveconfig_changes_dns_hostname_and_permissions(files, kind):
    mod, source = files
    path = mod.prepare(kind, "office", {"vpn.example": "192.0.2.1"})
    path.write_text(path.read_text().replace("10.0.0.2/32", "10.0.0.8/32"))
    mod.finish(kind, "office", save=True)
    assert "Address = 10.0.0.8/32" in source.read_text()
    assert "Endpoint = vpn.example:51820" in source.read_text()
    assert "DNS = 10.0.0.53" in source.read_text()
    assert stat.S_IMODE(source.stat().st_mode) == 0o640
    assert not path.parent.exists()


def test_failed_connect_discards_runtime_without_saving(files):
    mod, source = files
    path = mod.prepare("wg", "office", {"vpn.example": "192.0.2.1"})
    path.write_text("broken runtime")
    mod.finish("wg", "office", save=False)
    assert source.read_text() == WG
    assert not path.parent.exists()


def test_discard_cleans_a_prepare_interrupted_before_snapshot_write(files):
    mod, source = files
    mod.RUNTIME.mkdir(mode=0o700)
    directory = mod.RUNTIME / "wg-office"
    directory.mkdir(mode=0o700)
    mod.finish("wg", "office", save=False)
    assert not directory.exists()
    assert source.read_text() == WG


def test_saveconfig_off_never_rewrites_source(files):
    mod, source = files
    source.write_text(WG.replace("SaveConfig = true", "SaveConfig = false"))
    original = source.read_text()
    path = mod.prepare("wg", "office", {"vpn.example": "192.0.2.1"})
    path.write_text("different runtime")
    mod.finish("wg", "office", save=True)
    assert source.read_text() == original


@pytest.mark.parametrize(
    "kind,name",
    [
        ("bad", "office"),
        ("wg", "../other"),
        ("wg", "-option"),
        ("wg", "a" * 16),
        ("wg", "é"),
        ("wg", "a\u0661"),
        ("ovpn", "office²"),
    ],
)
def test_paths_and_options_cannot_select_profiles(files, kind, name):
    mod, source = files
    with pytest.raises(ValueError):
        mod.prepare(kind, name, {})
    assert source.read_text() == WG


@pytest.mark.parametrize("action", ["current", "finish"])
def test_dangling_runtime_link_is_not_treated_as_absent(files, tmp_path, action):
    mod, _ = files
    mod.RUNTIME.mkdir(mode=0o700)
    (mod.RUNTIME / "wg-office").symlink_to(tmp_path / "missing")
    operation = getattr(mod, action)
    kwargs = {"save": False} if action == "finish" else {}
    with pytest.raises(PermissionError):
        operation("wg", "office", **kwargs)


def test_successful_save_with_extra_runtime_file_does_not_block_reconnect(files):
    mod, source = files
    path = mod.prepare("wg", "office", {"vpn.example": "192.0.2.1"})
    (path.parent / "admin-note").write_text("keep this data")
    mod.finish("wg", "office", save=True)
    assert not path.parent.exists()
    assert "Endpoint = vpn.example:51820" in source.read_text()
    assert any(
        p.read_text() == "keep this data" for p in mod.RUNTIME.glob(".finished-*/admin-note")
    )
    again = mod.prepare("wg", "office", {"vpn.example": "192.0.2.2"})
    assert "Endpoint = 192.0.2.2:51820" in again.read_text()


def test_failed_save_retains_private_recovery_state(files, monkeypatch):
    mod, source = files
    path = mod.prepare("wg", "office", {"vpn.example": "192.0.2.1"})

    def fail(*args):
        raise OSError("disk full")

    monkeypatch.setattr(mod.os, "replace", fail)
    with pytest.raises(OSError, match="disk full"):
        mod.finish("wg", "office", save=True)
    assert source.read_text() == WG
    assert path.exists()
    assert (path.parent / ".source").exists()


def test_symlink_profile_and_unsafe_runtime_are_refused(files, tmp_path):
    mod, source = files
    linked = source.with_name("linked.conf")
    linked.symlink_to(source)
    with pytest.raises(OSError):
        mod.prepare("wg", "linked", {"vpn.example": "192.0.2.1"})
    mod.RUNTIME.mkdir(mode=0o755)
    with pytest.raises(PermissionError):
        mod.prepare("wg", "office", {"vpn.example": "192.0.2.1"})
    assert source.read_text() == WG
