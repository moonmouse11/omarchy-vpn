import json
import runpy
import subprocess
import sys
import time
from pathlib import Path

import pytest

import config
import vpn_manager
from app.spawn import MANAGER
from providers.base import ActionResult, VPNConnection

SRC = Path(__file__).resolve().parent.parent / "src"
_MANAGER = SRC / "vpn_manager.py"
# conftest fakes subprocess.Popen; --status probe needs a real child (see test_lazyimports.py).
_REAL_RUN = subprocess.run
_REAL_POPEN = subprocess.Popen


@pytest.fixture(autouse=True)
def _real_subprocess_for_status_probe(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", _REAL_POPEN)


class FakeProvider:
    def __init__(self, name, conns):
        self.name = name
        self._conns = conns

    def connections(self):
        return self._conns


def _hermetic_status_env(tmp_path: Path) -> None:
    import delayping
    import fsutil
    import killswitch
    import providers

    killswitch.STATE_CACHE = tmp_path / "killswitch-state.json"
    fsutil.write_json_atomic(killswitch.STATE_CACHE, {"at": time.time(), "on": False})
    killswitch.RESOLVED_CACHE = tmp_path / "resolved-ips.json"
    killswitch.RESOLV_CONF = tmp_path / "resolv.conf"
    delayping.PROGRESS = tmp_path / "ping-progress.json"
    providers.ALL_PROVIDERS = []


def patch_env(
    monkeypatch, providers, cfg=None, traffic="↓ 1 MiB  ↑ 2 MiB", rate="↓ 3 KiB/s ↑ 4 KiB/s"
):
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", providers)
    monkeypatch.setattr(vpn_manager.config, "load_config", lambda: cfg or config.Config())
    monkeypatch.setattr(vpn_manager, "iface_traffic", lambda iface: traffic)
    monkeypatch.setattr(vpn_manager, "iface_rate", lambda iface: rate)
    monkeypatch.setattr(vpn_manager, "sample_iface_traffic", lambda iface: None)
    monkeypatch.setattr(vpn_manager, "request_ip_update", lambda name: None)
    monkeypatch.setattr(vpn_manager.ipinfo, "status_line", lambda conn, age: "Exit: 9.9.9.9")


def _expect_manager_spawn(monkeypatch, fn, *expected_flags: str) -> None:
    calls = []

    def popen(cmd, **kw):
        calls.append((cmd, kw))

    monkeypatch.setattr(vpn_manager.subprocess, "Popen", popen)
    fn()
    assert len(calls) == 1
    cmd, kw = calls[0]
    assert cmd == [vpn_manager.sys.executable, str(MANAGER), *expected_flags]
    assert kw["start_new_session"] is True
    assert kw["stdout"] is vpn_manager.subprocess.DEVNULL
    assert kw["stderr"] is vpn_manager.subprocess.DEVNULL


def test_request_ip_update_spawns_vpn_manager(monkeypatch):
    _expect_manager_spawn(
        monkeypatch,
        lambda: vpn_manager.request_ip_update("nl"),
        "--update-ip",
        "nl",
    )


def test_request_dns_autotest_spawns_vpn_manager(monkeypatch):
    _expect_manager_spawn(monkeypatch, vpn_manager.request_dns_autotest, "--dns-autotest")


def test_emit_status_json_prints_get_status(monkeypatch, capsys):
    patch_env(monkeypatch, [])
    from app.status import emit_status_json

    emit_status_json()
    data = json.loads(capsys.readouterr().out.strip())
    assert data["class"] == "vpn-disconnected"
    assert data["text"] == " VPN"


def test_main_status_flag_prints_json(monkeypatch, capsys):
    patch_env(monkeypatch, [])
    monkeypatch.setattr(vpn_manager.sys, "argv", ["vpn_manager.py", "--status"])
    vpn_manager.main()
    data = json.loads(capsys.readouterr().out.strip())
    assert data["class"] == "vpn-disconnected"


def test_vpn_manager_main_early_status_entry(monkeypatch, tmp_path, capsys):
    """Widget path: __main__ + exactly --status (counts toward coverage in-process)."""
    _hermetic_status_env(tmp_path)
    monkeypatch.setattr(sys, "argv", [str(_MANAGER), "--status"])
    with pytest.raises(SystemExit):
        runpy.run_path(str(_MANAGER), run_name="__main__")
    data = json.loads(capsys.readouterr().out.strip())
    assert data["class"] == "vpn-disconnected"
    assert "panel" in data


def test_vpn_manager_main_non_status_argv_uses_cli(monkeypatch, tmp_path):
    """More than two argv entries skip the fast path and call app.cli.main."""
    _hermetic_status_env(tmp_path)
    monkeypatch.setattr(sys, "argv", [str(_MANAGER), "--install-wizard"])
    with pytest.raises(SystemExit):
        runpy.run_path(str(_MANAGER), run_name="__main__")


def test_vpn_manager_main_status_entry_subprocess():
    """Same as early entry, in a fresh interpreter (regression guard)."""
    probe = f"""
import runpy
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, {str(SRC)!r})
tmp = Path(tempfile.mkdtemp())
import delayping
import fsutil
import killswitch
import providers

killswitch.STATE_CACHE = tmp / "killswitch-state.json"
fsutil.write_json_atomic(killswitch.STATE_CACHE, {{"at": time.time(), "on": False}})
killswitch.RESOLVED_CACHE = tmp / "resolved-ips.json"
killswitch.RESOLV_CONF = tmp / "resolv.conf"
delayping.PROGRESS = tmp / "ping-progress.json"
providers.ALL_PROVIDERS = []
sys.argv = [{str(_MANAGER)!r}, "--status"]
runpy.run_path({str(_MANAGER)!r}, run_name="__main__")
"""
    out = _REAL_RUN(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    data = json.loads(out.stdout)
    assert data["class"] == "vpn-disconnected"


def test_disconnected(monkeypatch):
    patch_env(monkeypatch, [])
    status = vpn_manager.get_status()
    assert status["class"] == "vpn-disconnected"
    assert status["text"] == " VPN"


def test_single_active(monkeypatch):
    conn = VPNConnection(name="nl", provider="WireGuard", active=True, interface="wg0")
    patch_env(monkeypatch, [FakeProvider("WireGuard", [conn])])
    status = vpn_manager.get_status()
    assert status["text"] == " WireGuard: nl"
    assert status["class"] == ["vpn-connected", "vpn-wireguard"]
    assert "↓ 3 KiB/s ↑ 4 KiB/s" in status["tooltip"]  # rate, units per second
    assert "↓ 1 MiB  ↑ 2 MiB total" in status["tooltip"]  # totals, marked
    assert "Exit: 9.9.9.9" in status["tooltip"]


def test_multiple_active(monkeypatch):
    wg = VPNConnection(name="nl", provider="WireGuard", active=True, interface="wg0")
    happ = VPNConnection(name="de", provider="Happ", active=True)
    patch_env(monkeypatch, [FakeProvider("WireGuard", [wg]), FakeProvider("Happ", [happ])])
    status = vpn_manager.get_status()
    assert status["text"] == " WireGuard: nl (+1)"
    assert status["class"] == ["vpn-connected", "vpn-wireguard", "vpn-happ"]
    assert "Happ: de" in status["tooltip"]


def test_a_hidden_providers_tunnel_still_counts(monkeypatch):
    """⚙ Settings hides a protocol from the server list — a tunnel it has up
    (WireGuard autostart, NM) is still traffic in a tunnel, not "off"."""
    conn = VPNConnection(name="x", provider="Outline", active=True)
    cfg = config.Config(providers={"outline": False})
    patch_env(monkeypatch, [FakeProvider("Outline", [conn])], cfg=cfg)
    status = vpn_manager.get_status()
    assert "vpn-connected" in status["class"]


@pytest.mark.parametrize(
    ("up", "ipv6_off", "guard", "disabled"),
    [
        (True, False, True, True),
        (True, True, True, False),
        (False, False, True, False),
        (True, False, False, False),  # ⚙ IPv6 guard off: the user's call
    ],
)
def test_status_turns_ipv6_off_under_a_tunnel_the_plugin_didnt_start(
    monkeypatch, up, ipv6_off, guard, disabled
):
    """WireGuard autostart at boot: no guarded_connect ran, so --status is
    where IPv6 goes off — only when a tunnel is up, IPv6 is still on and the
    guard is on."""
    conn = VPNConnection(name="nl", provider="WireGuard", active=up)
    patch_env(monkeypatch, [FakeProvider("WireGuard", [conn])], cfg=config.Config(ipv6_guard=guard))
    calls = []
    monkeypatch.setattr(vpn_manager.ipv6guard, "is_disabled", lambda: ipv6_off)
    monkeypatch.setattr(
        vpn_manager.ipv6guard, "disable", lambda: calls.append("disable") or ActionResult(True, "")
    )
    monkeypatch.setattr(
        vpn_manager.ipv6guard, "enable", lambda: pytest.fail("status never enables")
    )
    vpn_manager.get_status()
    assert (calls == ["disable"]) is disabled


def test_no_traffic_when_no_interface(monkeypatch):
    conn = VPNConnection(name="de", provider="Happ", active=True, interface=None)
    patch_env(monkeypatch, [FakeProvider("Happ", [conn])], traffic=None)
    status = vpn_manager.get_status()
    assert "↓" not in status["tooltip"]


def test_connection_label_with_and_without_subscription():
    plain = VPNConnection(name="nl", provider="WireGuard", active=True)
    happ = VPNConnection(
        name="🇩🇪 Germany", provider="Happ", active=True, subscription_name="Provider C"
    )
    assert plain.label == "WireGuard: nl"
    assert happ.label == "Happ · Provider C: 🇩🇪 Germany"


def test_happ_status_shows_subscription_provider(monkeypatch):
    conn = VPNConnection(
        name="🇩🇪 Germany",
        provider="Happ",
        active=True,
        interface="happ-xray",
        subscription_id="1",
        subscription_name="Provider C",
    )
    patch_env(monkeypatch, [FakeProvider("Happ", [conn])])
    status = vpn_manager.get_status()
    assert status["text"] == " Happ · Provider C: 🇩🇪 Germany"
    assert "Happ · Provider C: 🇩🇪 Germany" in status["tooltip"]
