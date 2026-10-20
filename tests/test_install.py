from pathlib import Path

import installwizard

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
