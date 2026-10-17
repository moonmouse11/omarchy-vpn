"""make uninstall: the kill switch goes off — and is checked gone — first,
before the plugin, its script or the sudoers rule that runs it are removed. With Lockdown on,
rules left behind block all traffic until a reboot."""

from pathlib import Path

MAKEFILE = Path(__file__).parent.parent / "Makefile"


def _uninstall_recipe() -> list[str]:
    lines = MAKEFILE.read_text().splitlines()
    start = lines.index("uninstall:") + 1
    recipe = []
    for line in lines[start:]:
        if line and not line.startswith(("\t", "#")):
            break
        if line.startswith("\t"):
            recipe.append(line.strip())
    return recipe


def test_uninstall_turns_the_kill_switch_off_before_removing_it():
    recipe = _uninstall_recipe()

    def at(needle: str) -> int:
        return next(i for i, line in enumerate(recipe) if needle in line)

    off = at("happ-killswitch off")
    gone = at("nft list table inet happ-ks")
    # nothing is removed before the rules are gone: a failure keeps the plugin
    assert (off, gone) == (0, 1)
    assert (
        gone < at("rm -f /usr/local/bin/happ-killswitch") < at("rm -f /etc/sudoers.d/vpn-manager")
    )
    # a failed off must stop the recipe, not be ignored (make's "-" prefix)
    assert not recipe[off].startswith("-")
    assert not recipe[gone].lstrip("@").startswith("-")
