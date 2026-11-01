"""The installed entry uses isolated Python and a fixed root-owned import directory."""

import subprocess
import sys
from pathlib import Path

ENTRY = Path(__file__).resolve().parents[1] / "scripts" / "omarchy-vpn-incy-network"
_REAL_RUN = subprocess.run
_REAL_POPEN = subprocess.Popen


def test_real_root_package_has_no_user_backend_dependencies(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "Popen", _REAL_POPEN)
    trusted = tmp_path / "trusted"
    package = trusted / "incy"
    package.mkdir(parents=True)
    for name in ("__init__.py", "broker.py", "network.py", "privileged.py"):
        (package / name).write_text((ENTRY.parents[1] / "src" / "incy" / name).read_text())
    entry = tmp_path / "entry"
    entry.write_text(
        ENTRY.read_text()
        .replace("/usr/local/lib/omarchy-vpn", str(trusted))
        .replace("/usr/bin/python3", sys.executable)
    )
    entry.chmod(0o755)
    result = _REAL_RUN(
        [str(entry), "probe", "a" * 32],
        capture_output=True,
        text=True,
        env={},
        cwd=tmp_path,
    )
    assert result.returncode == 1
    assert "requires sudo caller identity" in result.stderr
    assert "Traceback" not in result.stderr


def test_entry_ignores_user_pythonpath_and_current_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "Popen", _REAL_POPEN)
    trusted = tmp_path / "trusted"
    package = trusted / "incy"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "privileged.py").write_text(
        "def main():\n    print('trusted helper')\n    return 23\n"
    )
    hostile = tmp_path / "hostile"
    (hostile / "incy").mkdir(parents=True)
    (hostile / "incy" / "__init__.py").write_text("raise RuntimeError('user code loaded')\n")
    (hostile / "sitecustomize.py").write_text("raise RuntimeError('user site loaded')\n")
    entry = tmp_path / "entry"
    entry.write_text(
        ENTRY.read_text()
        .replace("/usr/local/lib/omarchy-vpn", str(trusted))
        .replace("/usr/bin/python3", sys.executable)
    )
    entry.chmod(0o755)
    result = _REAL_RUN(
        [str(entry)],
        cwd=hostile,
        env={"PYTHONPATH": str(hostile)},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 23, result.stderr
    assert result.stdout == "trusted helper\n"
    assert "user code" not in result.stderr
