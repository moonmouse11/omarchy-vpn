"""uninstall.sh (make uninstall): the kill switch goes off — and is checked gone — first,
before the plugin, its script or the sudoers rule that runs it are removed. With Lockdown on,
rules left behind block all traffic until a reboot."""

import subprocess
from pathlib import Path

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


def test_uninstall_removes_root_incy_package(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "Popen", _REAL_POPEN)
    root = tmp_path / "root"
    helper = root / "bin" / "omarchy-vpn-incy-network"
    package = root / "lib" / "omarchy-vpn" / "incy"
    helper.parent.mkdir(parents=True)
    helper.write_text("unused")
    package.mkdir(parents=True)
    (package / "privileged.py").write_text("unused")
    shims = tmp_path / "shims"
    shims.mkdir()
    for name, body in {
        "sudo": 'exec "$@"',
        "nft": "exit 1",
        "omarchy": "exit 0",
        "omarchy-shell": "exit 0",
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
    assert result.returncode == 0, result.stdout + result.stderr
    assert not helper.exists()
    assert not package.parent.exists()


def test_make_uninstall_runs_the_script():
    lines = (Path(__file__).parent.parent / "Makefile").read_text().splitlines()
    assert lines[lines.index("uninstall:") + 1].strip() == "@bash uninstall.sh"
