"""The graphical gate must verify runtime facts and refuse ordinary host execution."""

import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GUEST_SCRIPT = (ROOT / "tests" / "qml_vm_guest.sh").read_text()
_REAL_POPEN = subprocess.Popen
_REAL_RUN = subprocess.run


def _verifier():
    path = ROOT / "tests" / "qml_vm_verify.py"
    spec = importlib.util.spec_from_file_location("qml_vm_verify", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.verify


@pytest.fixture
def observations(tmp_path):
    for surface in ("panel", "window"):
        (tmp_path / f"{surface}-filtered.json").write_text(
            json.dumps(
                {
                    "fieldText": "City 200",
                    "appliedFilter": "City 200",
                    "serverNames": ["VM Region - City 200 - Server 200"],
                    "surface": surface,
                    "inactiveModelCount": 0,
                }
            )
        )
    (tmp_path / "typed-unapplied.json").write_text(
        json.dumps(
            {
                "fieldText": "City 200",
                "appliedFilter": "",
            }
        )
    )
    (tmp_path / "both-filtered.json").write_text(
        json.dumps(
            {
                "panelVisible": True,
                "windowVisible": True,
                "appliedFilter": "City 199",
                "panelCount": 2,
                "windowCount": 2,
                "panelText": "City 199",
                "windowText": "City 199",
                "panelNames": ["VM Region - City 199 - Server 199"],
                "windowNames": ["VM Region - City 199 - Server 199"],
            }
        )
    )
    viewport = {
        "cursorKey": "provider\nWindscribe",
        "cursorOffset": 120.0,
        "topKey": "provider\nWindscribe",
        "topOffset": 120.0,
        "activeContentY": 240.0,
    }
    for name in ("windscribe-selected", "expanded", "folded", "reexpanded"):
        (tmp_path / f"{name}.json").write_text(json.dumps(viewport))
    scrolled = {
        "cursorKey": "server\nwindscribe\nVM Region - City 035 - Server 035",
        "cursorOffset": 180.0,
        "topKey": "server\nwindscribe\nVM Region - City 030 - Server 030",
        "topOffset": -4.0,
        "activeContentY": 1400.0,
    }
    (tmp_path / "panel-scrolled-before-refresh.json").write_text(json.dumps(scrolled))
    (tmp_path / "panel-scrolled-after-refresh.json").write_text(
        json.dumps({**scrolled, "panelDelegateCreates": 0})
    )
    both_scrolled = {
        "panelContentY": 800.0,
        "panelTopKey": "server\nwindscribe\nVM Region - City 020 - Server 020",
        "panelTopOffset": 0.0,
        "windowContentY": 1600.0,
        "windowTopKey": "server\nwindscribe\nVM Region - City 050 - Server 050",
        "windowTopOffset": 0.0,
    }
    for name in ("both-scrolled-before-refresh", "both-scrolled-after-refresh"):
        (tmp_path / f"{name}.json").write_text(json.dumps(both_scrolled))
    for name, live in (("bar-label-short", "DE"), ("bar-label-long", "Netherlands")):
        (tmp_path / f"{name}.json").write_text(
            json.dumps(
                {
                    "requestedBarLabel": live,
                    "liveBarLabel": live,
                    "displayedBarLabel": "Germany",
                    "barButtonWidth": 112.0,
                    "panelCardX": 840.0,
                    "panelContentWidth": 400.0,
                }
            )
        )
    (tmp_path / "restore-race.json").write_text(
        json.dumps(
            {
                "raceExpectedKey": "server\nwindscribe\nVM Region - City 069 - Server 069",
                "panelTopKey": "server\nwindscribe\nVM Region - City 069 - Server 069",
                "panelTopOffset": 0.0,
            }
        )
    )
    force_target = {"provider": "WireGuard", "name": "vm-target", "subscription_id": "sub-42"}
    ordinary = ["--connect-result", "WireGuard", "vm-target", "sub-42"]
    force = ["--force-connect", "WireGuard", "vm-target", "sub-42"]
    for name, data in {
        "force-panel-open": {
            "forceConfirmOpen": True,
            "forceTarget": force_target,
            "commands": [ordinary],
        },
        "force-panel-cancelled": {
            "forceConfirmOpen": False,
            "forceTarget": None,
            "commands": [ordinary],
        },
        "force-window-open": {
            "forceConfirmOpen": True,
            "forceTarget": force_target,
            "commands": [ordinary],
        },
        "force-window-confirmed": {
            "forceConfirmOpen": False,
            "forceTarget": force_target,
            "commands": [ordinary, force],
        },
    }.items():
        (tmp_path / f"{name}.json").write_text(json.dumps(data))
    (tmp_path / "actions.log").write_text("")
    (tmp_path / "shell-journal.txt").write_text("clean runtime\n")
    (tmp_path / "windscribe-handover.json").write_text(
        json.dumps(
            {
                "events": [
                    "signal:SIGTERM:4242",
                    "signal:SIGKILL:4242",
                    "disconnect:new-owner",
                    "status:disconnected",
                    "target-connect",
                ],
                "windscribe_state": "disconnected",
                "target_connected": True,
                "old_pid": 4242,
                "old_exitcode": -9,
                "old_alive": False,
            }
        )
    )
    return tmp_path


def test_guest_captures_expanded_folded_and_scrolled_geometry():
    assert "assert len(x['serverNames']) == 202" in GUEST_SCRIPT
    for image in ("panel-expanded.png", "panel-folded.png", "panel-scrolled.png"):
        assert f'grim "$OUT/{image}"' in GUEST_SCRIPT
    for snapshot in (
        "windscribe-selected",
        "panel-scrolled-before-refresh",
        "panel-scrolled-after-refresh",
        "both-scrolled-before-refresh",
        "both-scrolled-after-refresh",
        "bar-label-short",
        "bar-label-long",
        "restore-race",
    ):
        assert f"snapshot {snapshot}" in GUEST_SCRIPT


def test_runtime_verifier_accepts_full_filter_on_both_surfaces(observations):
    _verifier()(observations)


@pytest.mark.parametrize(
    ("file_name", "content_field", "key_field"),
    [
        ("panel-scrolled-after-refresh.json", "activeContentY", "topKey"),
        ("both-scrolled-after-refresh.json", "windowContentY", "windowTopKey"),
    ],
)
def test_runtime_verifier_rejects_a_model_rebuild_viewport_jump(
    observations, file_name, content_field, key_field
):
    path = observations / file_name
    data = json.loads(path.read_text())
    data[content_field] = 0
    data[key_field] = "provider\nWindscribe"
    path.write_text(json.dumps(data))

    with pytest.raises(ValueError):
        _verifier()(observations)


def test_runtime_verifier_rejects_open_panel_moving_with_a_longer_bar_label(observations):
    path = observations / "bar-label-long.json"
    data = json.loads(path.read_text())
    data["displayedBarLabel"] = "Netherlands"
    data["barButtonWidth"] = 164.0
    data["panelCardX"] = 866.0
    path.write_text(json.dumps(data))

    with pytest.raises(ValueError):
        _verifier()(observations)


def test_runtime_verifier_rejects_delegate_recreation_on_same_size_refresh(observations):
    path = observations / "panel-scrolled-after-refresh.json"
    data = json.loads(path.read_text())
    data["panelDelegateCreates"] = 12
    path.write_text(json.dumps(data))

    with pytest.raises(ValueError):
        _verifier()(observations)


def test_runtime_verifier_rejects_an_older_deferred_restore_winning(observations):
    path = observations / "restore-race.json"
    data = json.loads(path.read_text())
    data["panelTopKey"] = "server\nwindscribe\nVM Region - City 009 - Server 009"
    path.write_text(json.dumps(data))

    with pytest.raises(ValueError):
        _verifier()(observations)


def test_guest_exercises_force_cancel_and_confirm_without_real_actions():
    assert "auditStartForce" in GUEST_SCRIPT
    assert "snapshot force-panel-open" in GUEST_SCRIPT
    assert "snapshot force-panel-cancelled" in GUEST_SCRIPT
    assert "snapshot force-window-open" in GUEST_SCRIPT
    assert "snapshot force-window-confirmed" in GUEST_SCRIPT
    assert "wtype -k Escape" in GUEST_SCRIPT
    assert "wtype -k Return" in GUEST_SCRIPT


@pytest.mark.parametrize(
    ("file_name", "field", "bad_value"),
    [
        ("force-panel-cancelled.json", "forceConfirmOpen", True),
        ("force-panel-cancelled.json", "forceTarget", {"provider": "WireGuard"}),
        ("force-window-confirmed.json", "commands", [["--connect-result"]]),
        ("force-window-confirmed.json", "commands", [["--force-connect", "wrong"]]),
    ],
)
def test_runtime_verifier_rejects_broken_force_confirmation(
    observations, file_name, field, bad_value
):
    path = observations / file_name
    data = json.loads(path.read_text())
    data[field] = bad_value
    path.write_text(json.dumps(data))

    with pytest.raises(ValueError):
        _verifier()(observations)


@pytest.mark.parametrize("damage", ["truncated", "extra-row", "wrong-row", "action", "qml-error"])
def test_runtime_verifier_rejects_the_previous_failures(observations, damage):
    if damage == "action":
        (observations / "actions.log").write_text("windscribe-cli connect -n City 200\n")
    elif damage == "qml-error":
        (observations / "shell-journal.txt").write_text("Invalid alias reference\n")
    else:
        path = observations / "panel-filtered.json"
        data = json.loads(path.read_text())
        if damage == "truncated":
            data["fieldText"] = "C"
        elif damage == "extra-row":
            data["serverNames"].append("unexpected")
        else:
            data["serverNames"] = ["wrong server"]
        path.write_text(json.dumps(data))
    verify = _verifier()
    with pytest.raises(ValueError):
        verify(observations)


@pytest.mark.parametrize(
    "damage",
    [
        "still-connecting",
        "target-not-connected",
        "old-alive",
        "old-exited-normally",
        "wrong-order",
    ],
)
def test_runtime_verifier_rejects_failed_windscribe_handover(observations, damage):
    path = observations / "windscribe-handover.json"
    data = json.loads(path.read_text())
    if damage == "still-connecting":
        data["windscribe_state"] = "connecting"
    elif damage == "target-not-connected":
        data["target_connected"] = False
    elif damage == "old-alive":
        data["old_alive"] = True
    elif damage == "old-exited-normally":
        data["old_exitcode"] = 0
    else:
        data["events"] = ["target-connect", "disconnect:new-owner", "status:disconnected"]
    path.write_text(json.dumps(data))

    verify = _verifier()
    with pytest.raises(ValueError):
        verify(observations)


def test_runtime_verifier_rejects_missing_windscribe_handover(observations):
    (observations / "windscribe-handover.json").unlink()

    verify = _verifier()
    with pytest.raises(FileNotFoundError):
        verify(observations)


def test_runtime_verifier_rejects_missing_evidence(observations):
    (observations / "actions.log").unlink()
    verify = _verifier()
    with pytest.raises((ValueError, FileNotFoundError)):
        verify(observations)


@pytest.mark.parametrize("damage", ["empty-window", "stale-window-filter", "window-hidden"])
def test_runtime_verifier_rejects_broken_simultaneously_visible_lists(observations, damage):
    path = observations / "both-filtered.json"
    data = json.loads(path.read_text())
    if damage == "empty-window":
        data["windowCount"] = 0
        data["windowNames"] = []
    elif damage == "stale-window-filter":
        data["windowText"] = "City 200"
    else:
        data["windowVisible"] = False
    path.write_text(json.dumps(data))
    verify = _verifier()
    with pytest.raises(ValueError):
        verify(observations)


@pytest.mark.parametrize("claimed_guest", [False, True])
def test_guest_script_refuses_host_before_executing_any_setup(tmp_path, monkeypatch, claimed_guest):
    monkeypatch.setattr(subprocess, "Popen", _REAL_POPEN)
    script = ROOT / "tests" / "qml_vm_guest.sh"
    env = dict(os.environ, HOME=str(tmp_path))
    env.pop("OMARCHY_VPN_DISPOSABLE_GUEST", None)
    if claimed_guest:
        env["OMARCHY_VPN_DISPOSABLE_GUEST"] = "1"
    before = set(tmp_path.iterdir())  # conftest may already create cache fixtures here
    result = _REAL_RUN(["bash", str(script)], env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 64
    assert "disposable" in result.stderr
    assert set(tmp_path.iterdir()) == before
