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
    dirs = {name: tmp_path / name for name in ("wg", "awg", "ovpn", "run", "proc", "systemd")}
    for d in dirs.values():
        d.mkdir()
    env = {
        "PATH": "/usr/bin:/bin",
        "WG_DIR": str(dirs["wg"]),
        "AWG_DIR": str(dirs["awg"]),
        "OVPN_DIR": str(dirs["ovpn"]),
        "PID_DIR": str(dirs["run"]),
        "PROC_DIR": str(dirs["proc"]),
        "SYSTEMD_DIR": str(dirs["systemd"]),
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


@pytest.mark.parametrize(
    "hook",
    ["PostUp = bash -c id", "PreUp = x", "postdown = x", "  PreDown = x", "PostUp = echo don't"],
)
def test_import_refuses_wireguard_hooks(tree, hook):
    result = tree("import", "wg", "evil", stdin=f"[Interface]\n{hook}\n")
    assert result.returncode != 0
    assert "run as root" in result.stderr
    assert list(tree.dirs["wg"].iterdir()) == []  # not even the temp file


@pytest.mark.parametrize(
    "line",
    [
        "up /tmp/x",
        "route-up /tmp/x",
        "plugin /x.so",
        "log /etc/x",
        "management 0.0.0.0 1337",
        # openvpn reads all three as route-up (checked on 2.7.8): a denylist missed them
        "--route-up /tmp/x",
        '"route-up" /tmp/x',
        "setenv opt route-up /tmp/x",
        # code or file reads no denylist named (dns-updown is new in 2.7)
        "dns-updown /tmp/x",
        "pkcs11-providers /tmp/x.so",
        "providers /tmp/x.so",
        "auth-user-pass /etc/shadow",
        # the --up script's environment: the dns script runs as root
        "setenv LD_PRELOAD /tmp/x.so",
        "<connection>\nremote h 1194\nroute-up /tmp/x\n</connection>",
        "<x509-track>\nx\n</x509-track>",
        # openvpn ends a block on a line that only starts with the tag
        "<ca>\nx\n</ca>x\nroute-up /tmp/x\n<ca>\ny\n</ca>",
        # file arguments root would read: only inline blocks
        "ca /tmp/x",
        "tls-auth /tmp/x 1",
        "http-proxy h 8080 /tmp/x basic",
        "socks-proxy h 1080 /tmp/x",
        # the dns script's revert needs root
        "user nobody",
        # `endpoints` (kill switch whitelist, ping) reads only a plain remote
        "--remote h 1194",
        # openvpn reads a line in 256-byte pieces
        "remote " + "h" * 250 + " route-up /tmp/x",
    ],
)
def test_import_refuses_openvpn_scripts_and_file_writes(tree, line):
    result = tree("import", "ovpn", "evil", stdin=f"client\nremote h 1194\n{line}\n")
    assert result.returncode != 0
    assert list(tree.dirs["ovpn"].iterdir()) == []


def test_openvpn_import_keeps_harmless_lookalikes(tree):
    ok = "client\nremote vpn.example 1194 udp\nremote-cert-tls server\ndown-pre\n"
    assert tree("import", "ovpn", "us.east_udp", stdin=ok).returncode == 0
    assert tree("endpoints", "ovpn", "us.east_udp").stdout == "remote vpn.example 1194 udp\n"


def test_openvpn_import_keeps_a_typical_provider_config(tree):
    ok = (
        "# provider export\r\n"
        "client\r\ndev tun\r\nproto udp\r\nremote nl1.vpn.example 1194\r\n"
        "resolv-retry infinite\nnobind\npersist-key\npersist-tun\n"
        "remote-cert-tls server\ncipher AES-256-GCM\nauth SHA512\nverb 3\n"
        "auth-user-pass\nsetenv opt block-outside-dns\n--key-direction 1\n"
        "route-ipv6 ::/0\nblock-ipv6\ntopology subnet\ntls-timeout 2\nreplay-window 64\n"
        "<ca>\n-----BEGIN CERTIFICATE-----\nup /not/a/directive\n-----END CERTIFICATE-----\n</ca>\n"
        "<tls-crypt>\nx\n</tls-crypt>\n"
    )
    result = tree("import", "ovpn", "nl", stdin=ok)
    assert result.returncode == 0, result.stderr


def test_import_never_replaces_a_profile_that_appears_meanwhile(tree, tmp_path):
    """Two imports racing: both pass the "exists?" check; the hard link makes
    the later one fail instead of silently replacing the first."""
    dest = tree.dirs["wg"] / "home.conf"
    shim = tmp_path / "bin"
    shim.mkdir()
    # stands in for the other import: the profile appears right after the check
    (shim / "head").write_text(f'#!/bin/sh\necho first > "{dest}"\nexec /usr/bin/head "$@"\n')
    (shim / "head").chmod(0o755)
    result = tree("import", "wg", "home", stdin=WG, extra_env={"PATH": f"{shim}:/usr/bin:/bin"})
    assert "already exists" in result.stderr
    assert dest.read_text() == "first\n"
    assert [p.name for p in tree.dirs["wg"].iterdir()] == ["home.conf"]  # no temp left


def test_import_refuses_an_existing_profile_and_a_huge_one(tree):
    tree("import", "wg", "home", stdin=WG)
    assert "already exists" in tree("import", "wg", "home", stdin=WG).stderr
    assert "1 MiB" in tree("import", "wg", "big", stdin="x" * (1024 * 1024 + 1)).stderr


@pytest.mark.parametrize("name", ["../x", "a/b", "-x", ".hidden", "", "a" * 65, "a b"])
def test_names_are_never_paths_or_options(tree, name):
    result = tree("up", "wg", name)
    assert result.returncode != 0
    assert "invalid profile name" in result.stderr


@pytest.mark.parametrize("kind", ["wg", "awg"])
def test_wireguard_names_fit_an_interface_name(tree, kind):
    """wg-quick reads a name over 15 chars as a path from root's cwd."""
    result = tree("up", kind, "a" * 16)
    assert result.returncode != 0
    assert "at most 15 characters" in result.stderr
    assert tree("import", kind, "a" * 15, stdin=WG).returncode == 0
    assert tree("import", "ovpn", "a" * 16, stdin="client\nremote h 1194\n").returncode == 0


def test_a_long_named_profile_from_before_the_cap_can_still_be_deleted(tree):
    """rm never runs wg-quick: the path is built by the helper."""
    old = tree.dirs["wg"] / f"{'a' * 16}.conf"
    old.write_text(WG)
    assert tree("rm", "wg", "a" * 16).stdout.startswith(f"rm -f {old} ")


def test_unknown_kind_and_verb_are_refused(tree):
    assert "unknown kind" in tree("up", "zz", "home").stderr
    tree("import", "wg", "home", stdin=WG)
    assert "unknown command" in tree("cat", "wg", "home").stderr


def test_up_down_autostart_rm_run_fixed_commands(tree):
    tree("import", "wg", "home", stdin=WG)
    up_lines = tree("up", "wg", "home").stdout.strip().splitlines()
    assert up_lines[-1] == "wg-quick up home"
    if len(up_lines) == 2:
        assert "disable_ipv6=0" in up_lines[0]
    assert tree("down", "awg", "home").stdout == "awg-quick down home\n"


def test_down_deletes_interface_when_quick_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", _REAL_POPEN)
    bind = tmp_path / "bin"
    bind.mkdir()
    (bind / "wg-quick").write_text("#!/bin/sh\nexit 1\n")
    (bind / "ip").write_text(
        "#!/bin/sh\n"
        'if [ "$1" = link ] && [ "$2" = show ] && [ "$3" = dev ]; then exit 0; fi\n'
        'if [ "$1" = link ] && [ "$2" = delete ]; then echo "ip link delete dev $4"; exit 0; fi\n'
        "exit 1\n"
    )
    for script in bind.iterdir():
        script.chmod(0o755)
    env = {
        "PATH": f"{bind}:/usr/bin:/bin",
        "WG_DIR": str(tmp_path / "wg"),
        "AWG_DIR": str(tmp_path / "awg"),
        "OVPN_DIR": str(tmp_path / "ovpn"),
        "PID_DIR": str(tmp_path / "run"),
        "PROC_DIR": str(tmp_path / "proc"),
        "SYSTEMD_DIR": str(tmp_path / "systemd"),
    }
    for d in ("wg", "awg", "ovpn", "run", "proc", "systemd"):
        (tmp_path / d).mkdir()
    result = _REAL_RUN(
        ["bash", str(HELPER), "down", "wg", "orphan"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0
    assert "ip link delete dev orphan" in result.stdout


def test_wg_up_refuses_ipv6_only_allowedips(tree):
    v6only = (
        "[Interface]\nPrivateKey = x\n\n[Peer]\n"
        "PublicKey = y\nEndpoint = 1.2.3.4:51820\nAllowedIPs = ::/0\n"
    )
    tree("import", "wg", "home", stdin=v6only)
    conf = tree.dirs["wg"] / "home.conf"
    before = conf.read_text()
    result = tree("up", "wg", "home")
    assert result.returncode != 0
    assert "IPv6-only" in result.stderr
    assert conf.read_text() == before


def test_wg_up_strips_ipv6_allowedips_then_restores_config(tree):
    v6 = (
        "[Interface]\nPrivateKey = x\n\n[Peer]\n"
        "PublicKey = y\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
    )
    tree("import", "wg", "home", stdin=v6)
    conf = tree.dirs["wg"] / "home.conf"
    before = conf.read_text()
    tree("up", "wg", "home")
    assert conf.read_text() == before
    assert "::/0" in before
    assert tree("autostart", "wg", "home", "on").stdout == "systemctl enable wg-quick@home\n"
    assert tree("autostart", "wg", "home", "off").stdout == "systemctl disable wg-quick@home\n"
    assert tree("rm", "wg", "home").stdout.startswith(f"rm -f {tree.dirs['wg']}/home.conf ")
    assert tree("rm", "ovpn", "home").stderr == "error: no ovpn profile named 'home'\n"
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


def test_audit_lists_configs_on_disk_that_run_root_commands(tree):
    """make install warns about configs that predate the helper: imports
    refuse hooks, but `up` runs whatever is already there."""
    (tree.dirs["wg"] / "clean.conf").write_text(WG)
    (tree.dirs["wg"] / "old.conf").write_text("[Interface]\nPostUp = iptables -A x\n")
    (tree.dirs["ovpn"] / "corp.ovpn").write_text("client\nup /etc/openvpn/up.sh\n")
    result = tree("audit")
    assert result.returncode == 0
    assert sorted(result.stdout.splitlines()) == [
        f"{tree.dirs['ovpn']}/corp.ovpn: up /etc/openvpn/up.sh",
        f"{tree.dirs['wg']}/old.conf: PostUp = iptables -A x",
    ]


def _enabled_units(tree, tmp_path, *units):
    """A fake systemctl: `is-enabled` is true only for these units."""
    fake = tmp_path / "systemctl"
    fake.write_text(
        '#!/bin/sh\n[ "$1" = is-enabled ] || { echo "systemctl $*"; exit 0; }\n'
        f'case "$3" in {"|".join(units) or "none"}) exit 0 ;; esac\nexit 1\n'
    )
    fake.chmod(0o755)
    return {"SYSTEMCTL": str(fake)}


def test_ipv6_boot_drops_in_for_autostarted_profiles_only(tree, tmp_path):
    """Autostarted tunnels come up before login: IPv6 goes off right before
    them (a drop-in), not on the bar's first --status."""
    for name in ("home", "work"):
        tree("import", "wg", name, stdin=WG)
    env = _enabled_units(tree, tmp_path, "wg-quick@home")
    result = tree("ipv6-boot", "on", extra_env=env)
    assert result.returncode == 0
    assert "daemon-reload" in result.stdout
    systemd = tree.dirs["systemd"]
    dropin = systemd / "wg-quick@home.service.d" / "omarchy-vpn-ipv6.conf"
    assert (
        "ExecStartPre=/usr/bin/sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in dropin.read_text()
    )
    assert not (systemd / "wg-quick@work.service.d").exists()  # no autostart, no drop-in


def test_ipv6_boot_off_and_deleted_profiles_lose_their_drop_ins(tree, tmp_path):
    tree("import", "wg", "home", stdin=WG)
    tree("import", "wg", "gone", stdin=WG)
    env = _enabled_units(tree, tmp_path, "wg-quick@home", "wg-quick@gone")
    tree("ipv6-boot", "on", extra_env=env)
    (tree.dirs["wg"] / "gone.conf").unlink()  # deleted outside the helper
    tree("ipv6-boot", "on", extra_env=env)
    systemd = tree.dirs["systemd"]
    assert not (systemd / "wg-quick@gone.service.d" / "omarchy-vpn-ipv6.conf").exists()
    assert (systemd / "wg-quick@home.service.d" / "omarchy-vpn-ipv6.conf").exists()
    tree("ipv6-boot", "off", extra_env=env)  # ⚙ IPv6 guard off
    assert not (systemd / "wg-quick@home.service.d" / "omarchy-vpn-ipv6.conf").exists()
    assert "on | off" in tree("ipv6-boot", "maybe").stderr


def test_rm_also_removes_the_profiles_drop_in(tree):
    tree("import", "wg", "home", stdin=WG)
    dropin = tree.dirs["systemd"] / "wg-quick@home.service.d" / "omarchy-vpn-ipv6.conf"
    assert str(dropin) in tree("rm", "wg", "home").stdout


def test_rm_deletes_an_openvpn_profile(tree):
    tree("import", "ovpn", "nl", stdin="client\ndev tun\nremote 1.1.1.1 1194\n")
    conf = tree.dirs["ovpn"] / "nl.conf"
    assert conf.exists()
    assert tree("rm", "ovpn", "nl").stdout == f"rm -f {conf}\n"


def test_openvpn_autostart_enables_and_disables(tree):
    tree("import", "ovpn", "nl", stdin="client\nremote 1.1.1.1 1194\n")
    assert tree("autostart", "ovpn", "nl", "on").stdout == "systemctl enable openvpn-client@nl\n"
    assert tree("autostart", "ovpn", "nl", "off").stdout == "systemctl disable openvpn-client@nl\n"


def test_openvpn_autostart_rejects_bad_argument(tree):
    tree("import", "ovpn", "nl", stdin="client\nremote 1.1.1.1 1194\n")
    assert tree("autostart", "ovpn", "nl", "maybe").returncode != 0


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
