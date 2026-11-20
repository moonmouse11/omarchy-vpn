"""uninstall.sh (make uninstall): the kill switch goes off — and is checked gone — first,
before the plugin, its script or the sudoers rule that runs it are removed. With Lockdown on,
rules left behind block all traffic until a reboot."""

import subprocess
from pathlib import Path

import pytest

_REAL_RUN = subprocess.run
_REAL_POPEN = subprocess.Popen

SCRIPT = Path(__file__).parent.parent / "uninstall.sh"


def _commands() -> list[str]:
    lines = (line.strip() for line in SCRIPT.read_text().splitlines())
    return [line for line in lines if line and not line.startswith("#")]


def test_uninstall_turns_the_kill_switch_off_before_removing_it():
    commands = _commands()

    def at(needle: str) -> int:
        return next(i for i, line in enumerate(commands) if needle in line)

    # a failed off must stop the script, not be ignored
    assert at("set -e") < at("happ-killswitch off")
    off = at("happ-killswitch off")
    gone = at("nft list table inet happ-ks")
    assert off < gone
    # nothing is removed before the rules are gone: a failure keeps the install
    assert "exit 1" in commands[gone + 2]
    removals = [i for i, line in enumerate(commands) if "rm -" in line or "plugin disable" in line]
    assert removals
    assert min(removals) > gone
    sudoers = at("rm -f /etc/sudoers.d/vpn-manager")
    assert at("rm -f /usr/local/bin/happ-killswitch") < sudoers
    assert at("/usr/local/bin/omarchy-vpn-helper") < sudoers


@pytest.mark.parametrize("cleanup_fails", [False, True])
@pytest.mark.parametrize("legacy_helper", [False, True])
def test_uninstall_removes_root_incy_package(monkeypatch, tmp_path, cleanup_fails, legacy_helper):
    monkeypatch.setattr(subprocess, "Popen", _REAL_POPEN)
    root = tmp_path / "root"
    helper = root / "bin" / "omarchy-vpn-incy-network"
    package = root / "lib" / "omarchy-vpn" / "incy"
    helper.parent.mkdir(parents=True)
    dropin = root / "systemd/wg-quick@office.service.d/omarchy-vpn-ipv6.conf"
    dropin.parent.mkdir(parents=True)
    dropin.write_text("managed boot guard")
    helper.write_text("unused")
    boot_helper = helper.with_name("omarchy-vpn-helper")
    accepted = (
        '"$1 $2" = "ipv6-boot off"' if legacy_helper else '"$*" = "ipv6-boot off --uninstall"'
    )
    boot_helper.write_text(
        f"#!/bin/sh\ntest {accepted} || exit 42\n"
        + ("exit 7\n" if cleanup_fails else f'rm -f "{dropin}"\n')
    )
    boot_helper.chmod(0o755)
    dns_helper = helper.parent / "omarchy-vpn-dns-bootstrap"
    dns_helper.write_text("unused")
    package.mkdir(parents=True)
    (package / "privileged.py").write_text("unused")
    shims = tmp_path / "shims"
    shims.mkdir()
    for name, body in {
        "sudo": 'exec "$@"',
        "nft": "exit 1",
        "omarchy": "exit 0",
        "omarchy-shell": "exit 0",
        "systemctl": "exit 0",
    }.items():
        shim = shims / name
        shim.write_text(f"#!/bin/sh\n{body}\n")
        shim.chmod(0o755)
    script = tmp_path / "uninstall.sh"
    script.write_text(
        SCRIPT.read_text()
        .replace("/usr/local", str(root))
        .replace("/etc/sudoers.d", str(root / "sudoers"))
    )
    result = _REAL_RUN(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        env={"PATH": f"{shims}:/usr/bin:/bin", "HOME": str(tmp_path)},
    )
    if cleanup_fails:
        assert result.returncode == 7
        assert dropin.exists() and boot_helper.exists() and package.exists()
        return
    assert result.returncode == 0, result.stdout + result.stderr
    assert not dropin.exists()
    assert not helper.exists()
    assert not dns_helper.exists()
    assert not package.parent.exists()


def test_make_uninstall_runs_the_script():
    lines = (Path(__file__).parent.parent / "Makefile").read_text().splitlines()
    assert lines[lines.index("uninstall:") + 1].strip() == "@bash uninstall.sh"


def _at(commands, needle):
    return next(i for i, line in enumerate(commands) if needle in line)


def test_uninstall_stops_backend_before_deleting_it():
    commands = _commands()
    disable = _at(commands, "disable --now omarchy-vpn-backend.service")
    delete = _at(commands, 'rm -rf "$HOME/.local/share/omarchy-vpn"')
    unit = _at(commands, ".config/systemd/user/omarchy-vpn-backend.service")
    reload = _at(commands, "systemctl --user daemon-reload")
    assert disable < delete < unit < reload


def test_uninstall_removes_only_the_backend_socket():
    commands = _commands()
    assert not any("rm -rf" in c and "XDG_RUNTIME_DIR" in c for c in commands)
    removals = [c for c in commands if "rm -f" in c and "XDG_RUNTIME_DIR" in c]
    assert len(removals) == 1
    assert "omarchy-vpn/backend.sock" in removals[0]
    # only after proving it is a socket, and only with a runtime dir
    assert '-S "$XDG_RUNTIME_DIR/omarchy-vpn/backend.sock"' in removals[0]


def test_uninstall_service_needs_no_root():
    assert not any("sudo systemctl" in c for c in _commands())


def test_uninstall_stops_service_and_removes_only_its_socket(monkeypatch, tmp_path):
    import socket

    monkeypatch.setattr(subprocess, "Popen", _REAL_POPEN)
    runtime = tmp_path / "runtime"
    (runtime / "omarchy-vpn").mkdir(parents=True)
    sock = runtime / "omarchy-vpn" / "backend.sock"
    stale = socket.socket(socket.AF_UNIX)
    stale.bind(str(sock))
    stale.close()
    keep = runtime / "omarchy-vpn" / "other"
    keep.write_text("not ours")
    unit = tmp_path / ".config" / "systemd" / "user" / "omarchy-vpn-backend.service"
    unit.parent.mkdir(parents=True)
    unit.write_text("unit")
    backend = tmp_path / ".local" / "share" / "omarchy-vpn"
    backend.mkdir(parents=True)
    log = tmp_path / "systemctl.log"
    shims = tmp_path / "shims"
    shims.mkdir()
    for name, body in {
        "sudo": 'exec "$@"',
        "nft": "exit 1",
        "omarchy": "exit 0",
        "omarchy-shell": "exit 0",
        "systemctl": 'echo "$@" >> "' + str(log) + '"',
    }.items():
        shim = shims / name
        shim.write_text("#!/bin/sh\n" + body + "\n")
        shim.chmod(0o755)
    # never touch host paths: /usr/local and /etc/sudoers.d mapped into tmp
    root = tmp_path / "root"
    script = tmp_path / "uninstall.sh"
    script.write_text(
        SCRIPT.read_text()
        .replace("/usr/local", str(root))
        .replace("/etc/sudoers.d", str(root / "sudoers"))
    )
    env = {
        "PATH": str(shims) + ":/usr/bin:/bin",
        "HOME": str(tmp_path),
        "XDG_RUNTIME_DIR": str(runtime),
    }
    result = _REAL_RUN(["bash", str(script)], capture_output=True, text=True, env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not sock.exists()
    assert keep.read_text() == "not ours"
    assert not unit.exists()
    assert not backend.exists()
    assert log.read_text().splitlines() == [
        "--user disable --now omarchy-vpn-backend.service",
        "--user daemon-reload",
    ]
    # idempotent: a second run without socket/unit/service still succeeds
    again = _REAL_RUN(["bash", str(script)], capture_output=True, text=True, env=env)
    assert again.returncode == 0, again.stdout + again.stderr
