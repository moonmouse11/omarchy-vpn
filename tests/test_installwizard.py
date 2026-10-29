import json

import pytest

import config
import installwizard


class Unlistable:
    """/etc/wireguard on a fresh system: root 700, listing it fails."""

    def glob(self, pattern):
        raise PermissionError(13, "Permission denied")


@pytest.fixture
def bare(tmp_path, monkeypatch):
    """Nothing installed, nothing found: every probe redirected to empty spots."""
    for attr in ("WG_DIR", "AWG_DIR", "OVPN_DIR", "SUB_CACHE_DIR"):
        monkeypatch.setattr(installwizard, attr, tmp_path / attr.lower())
    monkeypatch.setattr(installwizard, "HAPPD", tmp_path / "no-happ/bin/happd")
    monkeypatch.setattr(installwizard, "KEYS_FILE", tmp_path / "keys.json")
    monkeypatch.setattr(installwizard, "RESOLV_CONF", tmp_path / "resolv.conf")
    monkeypatch.setattr(installwizard, "_run", lambda cmd, ok_codes=(0,): "")
    monkeypatch.setattr(installwizard.shutil, "which", lambda b: None)
    return tmp_path


def install_happd(root):
    happd = root / "no-happ/bin/happd"
    happd.parent.mkdir(parents=True)
    happd.write_text("")


def test_happ_dir_without_happd_is_not_found(bare):
    # the plugin talks to happd; a leftover /opt/happ isn't a Happ install
    (bare / "no-happ/bin").mkdir(parents=True)
    assert "Happ" not in installwizard.detect().notes


def test_nothing_found(bare):
    det = installwizard.detect()
    assert det.notes == {}
    assert not det.resolved_active
    assert det.resolvconf_provider == ""


def test_wireguard_found_by_profiles(bare, monkeypatch):
    wg = bare / "wg"
    wg.mkdir()
    (wg / "a.conf").write_text("")
    (wg / "b.conf").write_text("")
    monkeypatch.setattr(installwizard, "WG_DIR", wg)
    assert installwizard.detect().notes["WireGuard"] == "2 profiles"


def test_unlistable_dir_falls_back_to_the_binary(bare, monkeypatch):
    monkeypatch.setattr(installwizard, "WG_DIR", Unlistable())
    monkeypatch.setattr(
        installwizard.shutil, "which", lambda b: "/usr/bin/wg-quick" if b == "wg-quick" else None
    )
    assert installwizard.detect().notes == {"WireGuard": "installed"}


def test_enabled_unit_counts_as_found(bare, monkeypatch):
    def run(cmd, ok_codes=(0,)):
        if cmd[:2] == ["systemctl", "list-unit-files"] and "wg-quick@*" in cmd:
            return "wg-quick@home.service enabled enabled\n"
        return ""

    monkeypatch.setattr(installwizard, "_run", run)
    assert installwizard.detect().notes == {"WireGuard": "1 autostart"}


def test_openvpn_counts_conf_and_ovpn(bare, monkeypatch):
    ovpn = bare / "ovpn"
    ovpn.mkdir()
    (ovpn / "a.conf").write_text("")
    (ovpn / "b.ovpn").write_text("")
    monkeypatch.setattr(installwizard, "OVPN_DIR", ovpn)
    assert installwizard.detect().notes["OpenVPN"] == "2 profiles"


def test_happ_counts_subscriptions(bare, monkeypatch):
    install_happd(bare)
    subs = bare / "sub_cache_dir"
    subs.mkdir()
    (subs / "subscription-a.json").write_text("{}")
    (subs / "subscription-b.json").write_text("{}")
    (subs / "ping.json").write_text("{}")
    assert installwizard.detect().notes["Happ"] == "2 subscriptions"


def test_happ_installed_without_subscriptions(bare):
    install_happd(bare)
    assert installwizard.detect().notes["Happ"] == "installed"


def test_keys_counted_per_kind(bare):
    (bare / "keys.json").write_text(
        json.dumps(
            [
                {"kind": "vless", "host": "a"},
                {"kind": "vless", "host": "b"},
                {"kind": "ss", "host": "c"},
            ]
        )
    )
    notes = installwizard.detect().notes
    assert notes["VLESS"] == "2 keys"
    assert notes["Shadowsocks"] == "1 key"


def test_networkmanager_vpn_connections(bare, monkeypatch):
    def run(cmd, ok_codes=(0,)):
        return "vpn\nwireguard\n802-11-wireless\n" if cmd[0] == "nmcli" else ""

    monkeypatch.setattr(installwizard, "_run", run)
    assert installwizard.detect().notes == {"NetworkManager": "2 connections"}


def test_probe_error_is_not_found(bare, monkeypatch):
    def boom():
        raise RuntimeError("probe broke")

    monkeypatch.setitem(installwizard._PROBES, "WireGuard", boom)
    install_happd(bare)
    assert installwizard.detect().notes == {"Happ": "installed"}


def test_resolved_and_resolvconf_provider(bare, monkeypatch):
    def run(cmd, ok_codes=(0,)):
        if cmd == ["systemctl", "is-active", "systemd-resolved"]:
            return "active\n"
        if cmd == ["pacman", "-Qq", "resolvconf"]:
            return "openresolv\n"
        return ""

    monkeypatch.setattr(installwizard, "_run", run)
    det = installwizard.detect()
    assert det.resolved_active
    assert det.resolvconf_provider == "openresolv"


def test_resolv_stub(bare, monkeypatch):
    stub = bare / "stub-resolv.conf"
    stub.write_text("")
    monkeypatch.setattr(installwizard, "RESOLVED_STUB", stub)
    assert not installwizard.detect().resolv_stub  # missing file
    (bare / "resolv.conf").write_text("nameserver 8.8.8.8\n")
    assert not installwizard.detect().resolv_stub  # a plain file
    (bare / "resolv.conf").unlink()
    (bare / "resolv.conf").symlink_to(stub)
    assert installwizard.detect().resolv_stub


# ── Task 2: packages and hints ────────────────────────────────────────────────


def only(*visible, **kw):
    cfg = config.Config(**kw)
    cfg.providers = {p.lower(): p in visible for p in installwizard.PROTOCOLS}
    return cfg


def test_happ_only_needs_no_vpn_tools():
    assert installwizard.wanted_packages(only("Happ"), installwizard.Detection()) == ["python"]


def test_wireguard_on_resolved_gets_systemd_resolvconf():
    det = installwizard.Detection(resolved_active=True)
    assert installwizard.wanted_packages(only("WireGuard"), det) == [
        "python",
        "systemd-resolvconf",
        "wireguard-tools",
    ]


def test_without_resolved_gets_openresolv():
    assert installwizard.wanted_packages(only("OpenVPN"), installwizard.Detection()) == [
        "openresolv",
        "openvpn",
        "python",
    ]


def test_existing_resolvconf_provider_is_kept():
    det = installwizard.Detection(resolved_active=True, resolvconf_provider="openresolv")
    assert installwizard.wanted_packages(only("AmneziaWG"), det) == ["python"]


def test_switch_adds_systemd_resolvconf():
    det = installwizard.Detection(resolved_active=True, resolvconf_provider="openresolv")
    assert installwizard.wanted_packages(only("OpenVPN"), det, switch_resolvconf=True) == [
        "openvpn",
        "python",
        "systemd-resolvconf",
    ]


def test_killswitch_adds_nftables():
    packages = installwizard.wanted_packages(
        only("Happ", killswitch_mode="happ"), installwizard.Detection()
    )
    assert packages == ["nftables", "python"]


def test_missing_uses_pacman_T(monkeypatch):
    calls = []

    def run(cmd, ok_codes=(0,)):
        calls.append((cmd, ok_codes))
        return "openvpn\n"

    monkeypatch.setattr(installwizard, "_run", run)
    assert installwizard.missing_packages(["openvpn", "python"]) == ["openvpn"]
    assert calls == [(["pacman", "-T", "openvpn", "python"], (0, 127))]


def test_nothing_missing_is_empty(monkeypatch):
    monkeypatch.setattr(installwizard, "_run", lambda cmd, ok_codes=(0,): "")
    assert installwizard.missing_packages(["python"]) == []
    assert installwizard.missing_packages([]) == []


MISMATCH = installwizard.Detection(resolved_active=True, resolvconf_provider="openresolv")


def test_resolved_mismatch():
    assert installwizard.resolved_mismatch(only("OpenVPN"), MISMATCH)
    assert not installwizard.resolved_mismatch(only("Happ"), MISMATCH)
    # whatever provides resolvconf, or none (openresolv removed, pacman -S failed)
    for provider in ("systemd-resolvconf", ""):
        det = installwizard.Detection(resolved_active=True, resolvconf_provider=provider)
        assert installwizard.resolved_mismatch(only("WireGuard"), det)
    for det in (
        installwizard.Detection(resolved_active=False, resolvconf_provider="openresolv"),
        installwizard.Detection(
            resolved_active=True, resolvconf_provider="openresolv", resolv_stub=True
        ),
    ):
        assert not installwizard.resolved_mismatch(only("OpenVPN"), det)


def test_amneziawg_hint(monkeypatch):
    monkeypatch.setattr(installwizard.shutil, "which", lambda b: None)
    hint = (
        "AmneziaWG: install from AUR — amneziawg-tools, amneziawg-dkms "
        "(and linux-headers), or amneziawg-linux for stock kernel"
    )
    assert hint in installwizard.hints(only("AmneziaWG"), installwizard.Detection())
    assert hint not in installwizard.hints(only("WireGuard"), installwizard.Detection())
    monkeypatch.setattr(installwizard.shutil, "which", lambda b: "/usr/bin/awg-quick")
    assert hint not in installwizard.hints(only("AmneziaWG"), installwizard.Detection())


def test_happ_hint(tmp_path, monkeypatch):
    monkeypatch.setattr(installwizard, "HAPPD", tmp_path / "happ/bin/happd")
    hint = "Happ isn't installed (AUR: happ-desktop-bin) — Happ and VLESS/Shadowsocks keys need it"
    assert hint in installwizard.hints(only("VLESS"), installwizard.Detection())
    assert hint not in installwizard.hints(only("WireGuard"), installwizard.Detection())
    (tmp_path / "happ/bin").mkdir(parents=True)
    (tmp_path / "happ/bin/happd").write_text("")
    assert hint not in installwizard.hints(only("Happ"), installwizard.Detection())


def test_resolved_hint():
    hint = (
        "DNS: /etc/resolv.conf isn't systemd-resolved's stub — "
        "DNS pushed by OpenVPN isn't used. "
        "Re-run the installer and answer yes to switch to systemd-resolved."
    )
    assert hint in installwizard.hints(only("OpenVPN"), MISMATCH)
    assert hint not in installwizard.hints(only("OpenVPN"), MISMATCH, switched=True)
    assert hint not in installwizard.hints(only("OpenVPN"), installwizard.Detection())
