"""The graphical gate must verify runtime facts and refuse ordinary host execution."""

import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
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
    (tmp_path / "actions.log").write_text("")
    (tmp_path / "shell-journal.txt").write_text("clean runtime\n")
    return tmp_path


def test_runtime_verifier_accepts_full_filter_on_both_surfaces(observations):
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
    with pytest.raises(ValueError):
        _verifier()(observations)


def test_runtime_verifier_rejects_missing_evidence(observations):
    (observations / "actions.log").unlink()
    with pytest.raises((ValueError, FileNotFoundError)):
        _verifier()(observations)


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
    with pytest.raises(ValueError):
        _verifier()(observations)


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
