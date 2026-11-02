"""Root DNS import isolation; no backend or caller PYTHONPATH is trusted."""

import subprocess
import sys
from pathlib import Path

ENTRY = Path(__file__).resolve().parents[1] / "scripts/omarchy-vpn-dns-bootstrap"
_REAL_RUN = subprocess.run
_REAL_POPEN = subprocess.Popen


def test_dns_entry_is_isolated_and_uses_fixed_installed_root():
    assert ENTRY.is_file(), "fixed isolated bootstrap entry is missing"
    text = ENTRY.read_text()
    assert text.startswith("#!/usr/bin/python3 -I\n")
    assert 'sys.path.insert(0, "/usr/local/lib/omarchy-vpn")' in text
    assert "from dnscontrol import main" in text


def test_dns_entry_ignores_hostile_cwd_and_pythonpath(monkeypatch, tmp_path):
    assert ENTRY.is_file()
    monkeypatch.setattr(subprocess, "Popen", _REAL_POPEN)
    trusted, hostile = tmp_path / "trusted", tmp_path / "hostile"
    trusted.mkdir()
    hostile.mkdir()
    (trusted / "dnscontrol.py").write_text(
        "def main():\n    print('trusted DNS helper')\n    return 23\n"
    )
    (hostile / "dnscontrol.py").write_text("raise RuntimeError('untrusted module')\n")
    (hostile / "sitecustomize.py").write_text("raise RuntimeError('untrusted site')\n")
    entry = tmp_path / "entry"
    entry.write_text(
        ENTRY.read_text()
        .replace("/usr/local/lib/omarchy-vpn", str(trusted))
        .replace("/usr/bin/python3", sys.executable)
    )
    entry.chmod(0o755)
    result = _REAL_RUN(
        [str(entry)], cwd=hostile, env={"PYTHONPATH": str(hostile)}, capture_output=True, text=True
    )
    assert result.returncode == 23, result.stderr
    assert result.stdout == "trusted DNS helper\n"
