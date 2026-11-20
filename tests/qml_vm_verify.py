"""Validate disposable-VM runtime observations; screenshots alone cannot pass this gate."""

import json
import re
import signal
import sys
from pathlib import Path

RUNTIME_ERRORS = re.compile(
    r"Plugin widget omarchy-vpn failed|Invalid alias reference|"
    r"Type (?:AppWindow|ServerList) unavailable|ReferenceError|TypeError|binding loop",
    re.IGNORECASE,
)


def _verify_windscribe_handover(output: Path) -> None:
    data = json.loads((output / "windscribe-handover.json").read_text())
    events = data.get("events")
    if (
        data.get("windscribe_state") != "disconnected"
        or data.get("target_connected") is not True
        or data.get("old_alive") is not False
        or data.get("old_exitcode") != -signal.SIGKILL
        or not isinstance(data.get("old_pid"), int)
        or data["old_pid"] <= 1
        or not isinstance(events, list)
    ):
        raise ValueError(f"Windscribe handover did not finish safely: {data}")
    try:
        disconnect = events.index("disconnect:new-owner")
        disconnected = events.index("status:disconnected", disconnect + 1)
        target = events.index("target-connect", disconnected + 1)
    except ValueError as error:
        raise ValueError(f"Windscribe handover evidence is incomplete: {data}") from error
    if not disconnect < disconnected < target:
        raise ValueError(f"Windscribe target started before teardown: {data}")
    signals = [event for event in events if event.startswith("signal:")]
    if not any(event.startswith("signal:SIGKILL:") for event in signals) or any(
        event.rsplit(":", 1)[-1] != str(data["old_pid"]) for event in signals
    ):
        raise ValueError(f"Windscribe probe signalled an unexpected process: {data}")


def _verify_force_confirmation(output: Path) -> None:
    target = {"provider": "WireGuard", "name": "vm-target", "subscription_id": "sub-42"}
    ordinary = ["--connect-result", "WireGuard", "vm-target", "sub-42"]
    force = ["--force-connect", "WireGuard", "vm-target", "sub-42"]
    expected = {
        "force-panel-open.json": (True, target, [ordinary]),
        "force-panel-cancelled.json": (False, None, [ordinary]),
        "force-window-open.json": (True, target, [ordinary]),
        "force-window-confirmed.json": (False, target, [ordinary, force]),
    }
    for name, (opened, retained, commands) in expected.items():
        data = json.loads((output / name).read_text())
        if (
            data.get("forceConfirmOpen") is not opened
            or data.get("forceTarget") != retained
            or data.get("commands") != commands
        ):
            raise ValueError(f"Force confirmation evidence is invalid ({name}): {data}")


def _verify_viewport_stability(output: Path) -> None:
    def read(name: str) -> dict:
        return json.loads((output / f"{name}.json").read_text())

    header_states = [
        read(name) for name in ("windscribe-selected", "expanded", "folded", "reexpanded")
    ]
    expected_header = "provider\nWindscribe"
    baseline = header_states[0]
    if baseline.get("cursorKey") != expected_header or baseline.get("cursorOffset") is None:
        raise ValueError(f"Windscribe header anchor was not captured: {baseline}")
    for state in header_states[1:]:
        if (
            state.get("cursorKey") != expected_header
            or state.get("cursorOffset") is None
            or abs(state["cursorOffset"] - baseline["cursorOffset"]) > 2
        ):
            raise ValueError(f"fold/unfold moved the clicked header: {header_states}")

    before = read("panel-scrolled-before-refresh")
    after = read("panel-scrolled-after-refresh")
    if (
        before.get("activeContentY", 0) < 100
        or before.get("topKey") == ""
        or after.get("topKey") != before.get("topKey")
        or abs(after.get("topOffset", 0) - before.get("topOffset", 0)) > 2
        or abs(after.get("activeContentY", 0) - before.get("activeContentY", 0)) > 2
    ):
        raise ValueError(f"server refresh moved the viewport: before={before}, after={after}")

    both_before = read("both-scrolled-before-refresh")
    both_after = read("both-scrolled-after-refresh")
    if both_before.get("panelTopKey") == both_before.get("windowTopKey"):
        raise ValueError(f"dual-surface probe did not use distinct viewports: {both_before}")
    for surface in ("panel", "window"):
        content = f"{surface}ContentY"
        key = f"{surface}TopKey"
        offset = f"{surface}TopOffset"
        if (
            both_before.get(content, 0) < 100
            or both_before.get(key) == ""
            or both_after.get(key) != both_before.get(key)
            or abs(both_after.get(offset, 0) - both_before.get(offset, 0)) > 2
            or abs(both_after.get(content, 0) - both_before.get(content, 0)) > 2
        ):
            raise ValueError(
                f"dual-surface refresh moved {surface}: before={both_before}, after={both_after}"
            )


def verify(output: Path) -> None:
    _verify_windscribe_handover(output)
    _verify_force_confirmation(output)
    _verify_viewport_stability(output)
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
