"""Detached vpn_manager.py spawns (no happ/* import — avoids import cycles)."""

import subprocess
import sys
from pathlib import Path

MANAGER = Path(__file__).resolve().parent.parent / "vpn_manager.py"


def spawn_manager(*flags: str) -> None:
    """Background vpn_manager.py (DNS autotest, exit IP, subs/reputation refresh)."""
    subprocess.Popen(
        [sys.executable, str(MANAGER), *flags],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
