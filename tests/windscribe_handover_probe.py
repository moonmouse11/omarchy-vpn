#!/usr/bin/env python3
"""Process-level Windscribe handover probe with no real VPN or network effects."""

from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import signal
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import config  # noqa: E402
import vpn_manager  # noqa: E402
from app import switch as app_switch  # noqa: E402
from providers import windscribe as windscribe_shim  # noqa: E402
from providers.base import ActionResult, VPNConnection  # noqa: E402
from providers.common import interfaceclaims  # noqa: E402
from providers.vendor import windscribe as windscribe_impl  # noqa: E402


class _TargetProvider:
    name = "ProbeTarget"

    def __init__(self, connected, events) -> None:
        self.connected = connected
        self.events = events

    def connections(self) -> list[VPNConnection]:
        return []

    def connect(self, connection: VPNConnection) -> ActionResult:
        self.events.append("target-connect")
        self.connected.value = True
        return ActionResult(True, "Connected to probe target")

    def disconnect(self, connection: VPNConnection) -> ActionResult:
        return ActionResult(True, "Disconnected probe target")


def _old_connect(provider, connection: VPNConnection, state, result) -> None:
    state.old_pid = os.getpid()
    action = vpn_manager.guarded_connect(provider, connection)
    result["success"] = action.success
    result["message"] = action.message


def _validate(result: dict[str, Any]) -> None:
    events = result["events"]
    assert result["windscribe_state"] == "disconnected", result
    assert result["target_connected"] is True, result
    assert result["old_alive"] is False, result
    assert result["old_exitcode"] == -signal.SIGKILL, result
    assert int(result["old_pid"]) > 1, result
    assert "disconnect:new-owner" in events, result
    assert "status:disconnected" in events, result
    assert "target-connect" in events, result
    assert events.index("disconnect:new-owner") < events.index("status:disconnected"), result
    assert events.index("status:disconnected") < events.index("target-connect"), result
    signals = [event for event in events if event.startswith("signal:")]
    assert any(event.startswith("signal:SIGKILL:") for event in signals), result
    assert all(event.rsplit(":", 1)[1] == str(result["old_pid"]) for event in signals), result


def run_probe(workdir: Path) -> dict[str, object]:
    """Force-kill an old switch and prove its successor owns Windscribe teardown."""
    ctx = multiprocessing.get_context("fork")
    workdir.mkdir(parents=True, exist_ok=True)
    with ctx.Manager() as manager:
        state = manager.Namespace()
        state.connection = "disconnected"
        state.old_pid = 0
        state.teardown_started = False
        ready = manager.Event()
        events = manager.list()
        target_connected = manager.Value("b", False)
        old_result = manager.dict()

        old_provider = windscribe_impl.WindscribeProvider()
        target_provider = _TargetProvider(target_connected, events)
        old_connection = VPNConnection(name="Best Location", provider="Windscribe", active=False)
        target_connection = VPNConnection(name="Probe", provider=target_provider.name, active=False)

        def fake_run(args: list[str], timeout: int = 15) -> tuple[int, str]:
            if args == ["status"]:
                if state.connection != "disconnected" or state.teardown_started:
                    events.append(f"status:{state.connection}")
                value = str(state.connection).capitalize()
                return 0, (
                    "Internet connectivity: available\nLogin state: Logged in\n"
                    f"Firewall state: Off\nConnect state: {value}\n"
                )
            if args and args[0] == "connect":
                events.append("connect:old-owner")
                state.connection = "connecting"
                ready.set()
                return 0, "Connecting"
            if args == ["disconnect"]:
                if os.getpid() == state.old_pid:
                    events.append("disconnect:old-owner")
                    time.sleep(5)
                    return 0, "Disconnecting"
                events.append("disconnect:new-owner")
                state.teardown_started = True
                state.connection = "disconnected"
                return 0, "Disconnecting"
            raise AssertionError(args)

        original_signal_tree = app_switch._signal_switch_tree

        def signal_tree(pid: int, sig: signal.Signals) -> None:
            events.append(f"signal:{sig.name}:{pid}")
            original_signal_tree(pid, sig)

        patches = [
            (vpn_manager, "SWITCH_LOCK", workdir / "switch.lock"),
            (vpn_manager, "PROC", workdir / "proc"),
            (vpn_manager, "PREEMPT_GRACE", 0.1),
            (vpn_manager, "PREEMPT_WAIT", 1.0),
            (vpn_manager, "HANDOVER_WAIT", 1.0),
            (vpn_manager, "ALL_PROVIDERS", [old_provider, target_provider]),
            (vpn_manager, "_our_process", lambda pid, *args: pid == state.old_pid),
            (vpn_manager, "_signal_switch_tree", signal_tree),
            (vpn_manager, "_sync_ipv6_guard", lambda: None),
            (vpn_manager.logutil, "log", lambda message: None),
            (vpn_manager.killswitch, "is_enabled", lambda: False),
            (vpn_manager.killswitch, "mode", lambda: "off"),
            (vpn_manager.ipv6guard, "disable", lambda: ActionResult(True, "")),
            (app_switch.happ_provider, "app_connected", lambda: False),
            (app_switch.incy_provider, "app_connected", lambda: False),
            (config, "load_config", config.Config),
            (windscribe_shim.shutil, "which", lambda command: "/usr/bin/windscribe-cli"),
            (windscribe_shim, "_run", fake_run),
            (interfaceclaims, "get", lambda provider: None),
        ]
        originals = [(obj, name, getattr(obj, name)) for obj, name, _ in patches]
        for obj, name, value in patches:
            setattr(obj, name, value)

        old_process = ctx.Process(
            target=_old_connect,
            args=(old_provider, old_connection, state, old_result),
            name="windscribe-old-switch",
        )
        try:
            old_process.start()
            if not ready.wait(5):
                raise AssertionError("old Windscribe connect never reached Connecting")

            target_result = vpn_manager.guarded_connect(target_provider, target_connection)
            old_process.join(3)
            result: dict[str, object] = {
                "events": list(events),
                "windscribe_state": state.connection,
                "target_connected": bool(target_connected.value),
                "target_result": {
                    "success": target_result.success,
                    "message": target_result.message,
                },
                "old_pid": old_process.pid or 0,
                "old_exitcode": old_process.exitcode,
                "old_alive": old_process.is_alive(),
            }
            _validate(result)
            return result
        finally:
            if old_process.is_alive():
                old_process.kill()
                old_process.join(2)
            for obj, name, value in reversed(originals):
                setattr(obj, name, value)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="windscribe-handover-") as directory:
        result = run_probe(Path(directory))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("WINDSCRIBE_HANDOVER_PASS", json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
