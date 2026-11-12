"""Validate disposable-VM runtime observations; screenshots alone cannot pass this gate."""

import json
import re
import sys
from pathlib import Path

RUNTIME_ERRORS = re.compile(
    r"Plugin widget omarchy-vpn failed|Invalid alias reference|"
    r"Type (?:AppWindow|ServerList) unavailable|ReferenceError|TypeError|binding loop",
    re.IGNORECASE,
)


def verify(output: Path) -> None:
    if (output / "actions.log").read_text().strip():
        raise ValueError("filter typing invoked a vendor action")
    if RUNTIME_ERRORS.search((output / "shell-journal.txt").read_text()):
        raise ValueError("QML runtime error in journal")
    before = json.loads((output / "typed-unapplied.json").read_text())
    if before.get("fieldText") != "City 200" or before.get("appliedFilter") != "":
        raise ValueError("typing lost characters or applied before Enter")
    for surface in ("panel", "window"):
        data = json.loads((output / f"{surface}-filtered.json").read_text())
        if (
            data.get("fieldText") != "City 200"
            or data.get("appliedFilter") != "City 200"
            or data.get("serverNames") != ["VM Region - City 200 - Server 200"]
            or data.get("surface") != surface
            or data.get("inactiveModelCount") != 0
        ):
            raise ValueError(f"{surface}: filter text/result/inactive model mismatch: {data}")
    both = json.loads((output / "both-filtered.json").read_text())
    if (
        both.get("panelVisible") is not True
        or both.get("windowVisible") is not True
        or both.get("appliedFilter") != "City 199"
        or both.get("panelCount") != 2
        or both.get("windowCount") != 2
        or both.get("panelText") != "City 199"
        or both.get("windowText") != "City 199"
        or both.get("panelNames") != ["VM Region - City 199 - Server 199"]
        or both.get("windowNames") != ["VM Region - City 199 - Server 199"]
    ):
        raise ValueError(f"simultaneously visible lists lost model/filter state: {both}")


if __name__ == "__main__":
    verify(Path(sys.argv[1]))
    print("VM_QML_TEST_PASS: full filter, exactly one matching server, no actions/runtime errors")
