"""The window's Profiles: "+ Import" (--import) and a server row's right click
(--profile autostart|delete)."""

import io
import subprocess
from types import SimpleNamespace

import pytest

import vpn_manager
from providers.base import ActionResult, VPNConnection


class FakeProvider:
    def __init__(self, name, conns=()):
        self.name = name
        self._conns = list(conns)
        self.imported, self.toggled, self.deleted = [], [], []

    def connections(self):
        return self._conns

    def import_config(self, path):
        self.imported.append(path)
        return ActionResult(True, f"imported {path}")

    def toggle_autostart(self, conn):
        self.toggled.append(conn.name)
        return ActionResult(True, "toggled")

    def delete_config(self, conn):
        self.deleted.append(conn.name)
        return ActionResult(True, "deleted")


@pytest.fixture
def wg(monkeypatch):
    home = VPNConnection(name="home", provider="WireGuard", active=False)
    provider = FakeProvider("WireGuard", [home])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [provider, FakeProvider("Happ")])
    return provider


def _chooser(monkeypatch, rc, out="", err=""):
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        return SimpleNamespace(returncode=rc, stdout=out, stderr=err)

    monkeypatch.setattr(vpn_manager.subprocess, "run", run)
    return calls


def test_import_without_a_path_asks_the_file_chooser(wg, monkeypatch):
    calls = _chooser(monkeypatch, 0, "/home/u/home.conf\n")
    assert vpn_manager.run_import("WireGuard").success
    assert calls[0][0] == "omarchy-file-select"
    assert calls[0][calls[0].index("--extensions") + 1] == "conf"
    assert wg.imported == ["/home/u/home.conf"]


@pytest.mark.parametrize(
    ("provider", "extensions"), [("OpenVPN", "ovpn conf"), ("NetworkManager", "conf ovpn")]
)
def test_import_chooser_filters_by_the_providers_file_types(monkeypatch, provider, extensions):
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [FakeProvider(provider)])
    calls = _chooser(monkeypatch, 1)
    vpn_manager.run_import(provider)
    assert calls[0][calls[0].index("--extensions") + 1] == extensions


def test_import_cancelled_in_the_chooser_is_silent(wg, monkeypatch):
    _chooser(monkeypatch, 1)
    result = vpn_manager.run_import("WireGuard")
    assert result.success
    assert result.message == ""  # no bubble for a decision
    assert wg.imported == []


def test_import_reports_a_chooser_that_never_ran(wg, monkeypatch):
    _chooser(monkeypatch, 2, err="no portal")
    result = vpn_manager.run_import("WireGuard")
    assert not result.success
    assert "no portal" in result.message


def test_import_chooser_timeout_is_an_error(wg, monkeypatch):
    def run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(vpn_manager.subprocess, "run", run)
    assert not vpn_manager.run_import("WireGuard").success


def test_import_reads_a_key_from_stdin_not_argv(monkeypatch):
    """A key in argv shows in `ps` to every user: the window pipes it in."""
    keys = FakeProvider("VLESS")
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [keys])
    monkeypatch.setattr(vpn_manager.sys, "stdin", io.StringIO("  vless://secret@host:443#x\n"))
    assert vpn_manager.run_import("VLESS", "-").success
    assert keys.imported == ["vless://secret@host:443#x"]


def test_import_refuses_happ_and_an_empty_source(wg, monkeypatch):
    assert not vpn_manager.run_import("Happ", "/x.conf").success
    monkeypatch.setattr(vpn_manager.sys, "stdin", io.StringIO("   "))
    assert vpn_manager.run_import("WireGuard", "-").message == "Nothing to import"
    assert wg.imported == []


def test_profile_actions_reach_the_provider(wg):
    assert vpn_manager.run_profile_action("autostart", "WireGuard", "home").success
    assert vpn_manager.run_profile_action("delete", "WireGuard", "home").success
    assert (wg.toggled, wg.deleted) == (["home"], ["home"])


def test_profile_actions_refuse_unknown_profiles_and_unmanaged_providers(wg):
    assert not vpn_manager.run_profile_action("delete", "WireGuard", "nope").success
    assert not vpn_manager.run_profile_action("delete", "Happ", "home").success
    assert wg.deleted == []


def test_delete_refuses_an_active_profile(monkeypatch):
    """The real provider's guard, through the window's path: an active
    tunnel's config is never deleted (and no sudo runs)."""
    from providers.wireguard import WireGuardProvider

    wg = WireGuardProvider()
    home = VPNConnection(name="home", provider="WireGuard", active=True)
    monkeypatch.setattr(wg, "connections", lambda: [home])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg])
    monkeypatch.setattr(
        vpn_manager.subprocess, "run", lambda *a, **kw: pytest.fail("ran a command")
    )
    result = vpn_manager.run_profile_action("delete", "WireGuard", "home")
    assert not result.success
    assert "Disconnect" in result.message
