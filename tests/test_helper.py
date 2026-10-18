"""scripts/omarchy-vpn-helper — the only root entry point for WireGuard/
AmneziaWG/OpenVPN. Run for real (bash), against a temp tree: the directory
overrides and DRY_RUN (print, don't run) work only outside sudo."""

import subprocess
from pathlib import Path

import pytest

HELPER = Path(__file__).parent.parent / "scripts" / "omarchy-vpn-helper"
SRC = Path(__file__).parent.parent / "src"
# conftest replaces subprocess.run/Popen for every test; these are the real ones
_REAL_RUN = subprocess.run
_REAL_POPEN = subprocess.Popen


@pytest.fixture
def tree(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", _REAL_POPEN)
    dirs = {name: tmp_path / name for name in ("wg", "awg", "ovpn", "run", "proc")}
    for d in dirs.values():
        d.mkdir()
    env = {
        "PATH": "/usr/bin:/bin",
        "WG_DIR": str(dirs["wg"]),
        "AWG_DIR": str(dirs["awg"]),
        "OVPN_DIR": str(dirs["ovpn"]),
        "PID_DIR": str(dirs["run"]),
        "PROC_DIR": str(dirs["proc"]),
        "DRY_RUN": "1",
    }

    def helper(*args, stdin="", extra_env=None):
        return _REAL_RUN(
            ["bash", str(HELPER), *args],
            input=stdin,
            capture_output=True,
            text=True,
            env={**env, **(extra_env or {})},
            check=False,
        )

    helper.dirs = dirs
    return helper


WG = "[Interface]\nPrivateKey = SECRET\nDNS = 10.0.0.1\n\n[Peer]\nEndpoint = 1.2.3.4:51820\n"


def test_import_writes_the_config_0600_and_endpoints_never_show_keys(tree):
    assert tree("import", "wg", "home", stdin=WG).returncode == 0
    conf = tree.dirs["wg"] / "home.conf"
    assert conf.read_text() == WG
    assert conf.stat().st_mode & 0o777 == 0o600
    out = tree("endpoints", "wg", "home").stdout
    assert "SECRET" not in out
    assert out.splitlines() == ["[Interface]", "[Peer]", "Endpoint = 1.2.3.4:51820"]


@pytest.mark.parametrize("hook", ["PostUp", "PreUp", "postdown", "  PreDown"])
def test_import_refuses_wireguard_hooks(tree, hook):
    result = tree("import", "wg", "evil", stdin=f"[Interface]\n{hook} = bash -c id\n")
    assert result.returncode != 0
    assert "run as root" in result.stderr
    assert list(tree.dirs["wg"].iterdir()) == []  # not even the temp file


@pytest.mark.parametrize("line", ["up /tmp/x", "route-up /tmp/x", "plugin /x.so", "log /etc/x"])
def test_import_refuses_openvpn_scripts_and_file_writes(tree, line):
    result = tree("import", "ovpn", "evil", stdin=f"client\nremote h 1194\n{line}\n")
    assert result.returncode != 0
    assert list(tree.dirs["ovpn"].iterdir()) == []


def test_openvpn_import_keeps_harmless_lookalikes(tree):
    ok = "client\nremote vpn.example 1194 udp\nremote-cert-tls server\ndown-pre\n"
    assert tree("import", "ovpn", "us.east_udp", stdin=ok).returncode == 0
    assert tree("endpoints", "ovpn", "us.east_udp").stdout == "remote vpn.example 1194 udp\n"


def test_import_refuses_an_existing_profile_and_a_huge_one(tree):
    tree("import", "wg", "home", stdin=WG)
    assert "already exists" in tree("import", "wg", "home", stdin=WG).stderr
    assert "1 MiB" in tree("import", "wg", "big", stdin="x" * (1024 * 1024 + 1)).stderr


@pytest.mark.parametrize("name", ["../x", "a/b", "-x", ".hidden", "", "a" * 65, "a b"])
def test_names_are_never_paths_or_options(tree, name):
    result = tree("up", "wg", name)
    assert result.returncode != 0
    assert "invalid profile name" in result.stderr


def test_unknown_kind_and_verb_are_refused(tree):
    assert "unknown kind" in tree("up", "zz", "home").stderr
    tree("import", "wg", "home", stdin=WG)
    assert "unknown command" in tree("cat", "wg", "home").stderr


def test_up_down_autostart_rm_run_fixed_commands(tree):
    tree("import", "wg", "home", stdin=WG)
    assert tree("up", "wg", "home").stdout == "wg-quick up home\n"
    assert tree("down", "awg", "home").stdout == "awg-quick down home\n"
    assert tree("autostart", "wg", "home", "on").stdout == "systemctl enable wg-quick@home\n"
    assert tree("autostart", "wg", "home", "off").stdout == "systemctl disable wg-quick@home\n"
    assert tree("rm", "wg", "home").stdout == f"rm -f {tree.dirs['wg']}/home.conf\n"
    assert "wg / awg" in tree("rm", "ovpn", "home").stderr
    assert "no wg profile" in tree("up", "wg", "nope").stderr


def test_openvpn_up_runs_with_the_dns_script_and_fixed_flags(tree):
    tree("import", "ovpn", "nl", stdin="client\nremote h 1194\n")
    launch = tree("up", "ovpn", "nl").stdout.splitlines()[-1].split()
    assert launch[:3] == ["openvpn", "--config", f"{tree.dirs['ovpn']}/nl.conf"]
    assert "--persist-remote-ip" in launch
    assert launch[launch.index("--script-security") + 1] == "2"
    assert launch[launch.index("--up") + 1 : launch.index("--up") + 3] == [
        "/usr/local/bin/openvpn-dns-updown",
        "up",
    ]


@pytest.mark.parametrize(("comm", "killed"), [("openvpn", True), ("bash", False)])
def test_openvpn_down_kills_only_the_profiles_openvpn(tree, comm, killed):
    (tree.dirs["run"] / "client-nl.pid").write_text("42\n")
    (tree.dirs["proc"] / "42").mkdir()
    (tree.dirs["proc"] / "42" / "comm").write_text(f"{comm}\n")
    result = tree("down", "ovpn", "nl")
    assert ("kill 42" in result.stdout) is killed
    assert (result.returncode == 0) is killed


def test_overrides_are_ignored_under_sudo(tree):
    """Run via sudo (SUDO_USER set), the helper uses the real directories —
    a caller can't point root at a tree of its own."""
    tree("import", "wg", "home", stdin=WG)
    result = tree("endpoints", "wg", "home", extra_env={"SUDO_USER": "someone"})
    assert "SECRET" not in result.stdout
    assert "no wg profile" in result.stderr  # looked in /etc/wireguard, not the temp tree


def test_src_runs_sudo_only_through_the_narrow_entry_points():
    """The old broad sudoers rule is gone: a `sudo` call in src/ with anything
    but the helper, happ-killswitch or the IPv6 sysctl would just fail."""
    allowed = ("HELPER", "SCRIPT", '"sysctl"')
    offenders = [
        f"{path.relative_to(SRC)}:{n}: {line.strip()}"
        for path in SRC.rglob("*.py")
        for n, line in enumerate(path.read_text().splitlines(), 1)
        if '"sudo"' in line and not any(a in line for a in allowed)
    ]
    assert offenders == []
