import subprocess
from pathlib import Path

import pytest

import installwizard

# captured at import, before conftest's autouse fixtures fake subprocess.run
# and set subprocess.Popen to None (see test_lazyimports.py)
_REAL_RUN = subprocess.run
_REAL_POPEN = subprocess.Popen

INSTALL = Path(__file__).resolve().parent.parent / "install.sh"


def lines() -> list[str]:
    """install.sh's commands: comments and blank lines dropped."""
    stripped = (line.strip() for line in INSTALL.read_text().splitlines())
    return [line for line in stripped if line and not line.startswith("#")]


def index(needle: str) -> int:
    return next(i for i, line in enumerate(lines()) if needle in line)


def test_wizard_runs_before_any_sudo():
    assert index("--install-wizard") < index("sudo ")


def test_wizard_runs_with_dash_B():
    # nothing may be written under the plugin dir (hot reload), __pycache__ included
    assert "python3 -B" in lines()[index("--install-wizard")]


def test_cancelled_wizard_stops_the_install():
    line = lines()[index("--install-wizard")]
    assert "|| {" in line
    assert "exit 1" in " ".join(lines()[index("--install-wizard") : index("--install-wizard") + 3])


def test_no_resolv_conf_changes():
    cmds = lines()
    assert not any("resolvconf -u" in c for c in cmds)
    assert not any("rm /etc/resolv.conf" in c for c in cmds)
    writes = [c for c in cmds if "/etc/resolv.conf" in c and not c.startswith("echo")]
    assert writes == ["sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf"]
    # only after a yes: inside the switch branch
    assert index("SWITCH_RESOLVCONF") < index("ln -sf /run/systemd/resolve/stub-resolv.conf")


def test_switch_follows_the_wizard_mark():
    # the user's yes, not openresolv's presence: a re-run after a failed
    # pacman -S (openresolv already gone) must still link the stub
    mark = installwizard.RESOLV_STUB_MARK
    cmds = lines()
    switch = index(f'"{mark}"')
    assert "SWITCH_RESOLVCONF=1" in " ".join(cmds[switch : switch + 3])
    assert index("SWITCH_RESOLVCONF=1") < index("pacman -S")
    # the mark never reaches pacman
    assert index("MISSING=(") < index("pacman -S")


def test_openresolv_removed_only_for_the_switch():
    remove = index("pacman -R")
    assert "openresolv" in lines()[remove]
    assert "[[ -n $SWITCH_RESOLVCONF ]]" in " ".join(lines()[remove - 2 : remove])
    assert remove < index("pacman -S")


def test_pacman_only_for_missing():
    cmds = lines()
    install = index("pacman -S")
    assert '"${MISSING[@]}"' in cmds[install]
    assert "(( ${#MISSING[@]} ))" in cmds[install - 1] or any(
        "(( ${#MISSING[@]} ))" in c for c in cmds[install - 6 : install]
    )


def test_one_password_prompt_up_front():
    assert index("sudo -v") < index("pacman")


def test_no_trailing_configure():
    assert not any("--configure" in c for c in lines())


def test_wizard_output_goes_to_fd_3_not_a_path_in_argv():
    # no file path on the command line (Sonar S8707): the list comes back on fd 3
    line = lines()[index("--install-wizard")]
    assert "OMARCHY_VPN_WIZARD_FD=3 python3" in line
    assert '--install-wizard 3>"$PKG_FILE"' in line


def test_install_wizard_flag_takes_no_path(monkeypatch):
    import vpn_manager

    seen = []
    monkeypatch.setattr("sys.argv", ["vpn_manager.py", "--install-wizard"])
    monkeypatch.setenv("OMARCHY_VPN_WIZARD_FD", "3")
    monkeypatch.setattr(vpn_manager.os, "fstat", lambda fd: None)
    monkeypatch.setattr(
        "installwizard.run", lambda prompter, out: seen.append(out) or 0, raising=True
    )
    with pytest.raises(SystemExit):
        vpn_manager.main()
    assert seen == [installwizard.WIZARD_OUT]


def test_install_wizard_without_fd_3_refuses_before_any_question(monkeypatch):
    import vpn_manager

    asked = []
    monkeypatch.setattr("sys.argv", ["vpn_manager.py", "--install-wizard"])
    monkeypatch.setattr("installwizard.run", lambda *a: asked.append(a) or 0)
    monkeypatch.setenv("OMARCHY_VPN_WIZARD_FD", "3")
    monkeypatch.setattr(vpn_manager.os, "fstat", _closed)
    with pytest.raises(SystemExit) as e:
        vpn_manager.main()
    assert "3>" in str(e.value.code)  # how to run it, not a traceback
    assert asked == []  # nothing asked, config.json untouched


def test_install_wizard_ignores_an_fd_3_install_sh_did_not_open(monkeypatch):
    # a shell's own fd 3 would be truncated by WIZARD_OUT.write_text
    import vpn_manager

    asked = []
    monkeypatch.setattr("sys.argv", ["vpn_manager.py", "--install-wizard"])
    monkeypatch.setattr("installwizard.run", lambda *a: asked.append(a) or 0)
    monkeypatch.delenv("OMARCHY_VPN_WIZARD_FD", raising=False)
    monkeypatch.setattr(vpn_manager.os, "fstat", lambda fd: None)  # fd 3 open
    with pytest.raises(SystemExit) as e:
        vpn_manager.main()
    assert "install.sh" in str(e.value.code)
    assert asked == []


def _closed(fd):
    raise OSError(9, "Bad file descriptor")


def test_fd_3_reaches_what_install_sh_reads(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", _REAL_POPEN)
    # the real plumbing: bash's 3>file, a write to WIZARD_OUT, then mapfile
    src = Path(__file__).resolve().parent.parent / "src"
    write = (
        f"import sys; sys.path.insert(0, {str(src)!r}); import installwizard; "
        "installwizard.WIZARD_OUT.write_text('openvpn\\n:resolv-stub\\n')"
    )
    script = (
        'f=$(mktemp); python3 -c "$1" 3>"$f"; mapfile -t M < "$f"; rm "$f"; printf "%s|" "${M[@]}"'
    )
    out = _REAL_RUN(
        ["bash", "-c", script, "_", write], capture_output=True, text=True, check=True
    ).stdout
    assert out == "openvpn|:resolv-stub|"


def _run_install(monkeypatch, tmp_path, failing):
    """The real install.sh with its commands stubbed: `failing` exits 1, the rest 0."""
    monkeypatch.setattr(subprocess, "Popen", _REAL_POPEN)
    shims = tmp_path / "bin"
    shims.mkdir()
    for cmd in ("omarchy-shell", "python3", "sudo"):
        (shims / cmd).write_text(f"#!/bin/sh\nexit {int(cmd == failing)}\n")
        (shims / cmd).chmod(0o755)
    env = {"PATH": f"{shims}:/usr/bin:/bin", "HOME": str(tmp_path)}
    return _REAL_RUN(["bash", str(INSTALL)], capture_output=True, text=True, env=env)


def test_a_failed_root_step_says_setup_failed(monkeypatch, tmp_path):
    """Finish setup's terminal prints omarchy's "Done!" whatever the exit code:
    a failed step must say itself that setup didn't finish."""
    result = _run_install(monkeypatch, tmp_path, failing="sudo")
    assert result.returncode != 0
    assert "Setup failed" in result.stdout + result.stderr


def test_a_cancelled_wizard_is_not_a_failure(monkeypatch, tmp_path):
    result = _run_install(monkeypatch, tmp_path, failing="python3")
    assert "Cancelled" in result.stdout
    assert "Setup failed" not in result.stdout + result.stderr
