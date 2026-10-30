"""Start INCY's bundled xray via omarchy-vpn-helper (TUN needs root/CAP_NET_ADMIN)."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

import fsutil
from incy.paths import incy_xray
from incy.xray import asset_dir
from providers.common.helper import HELPER

STATE_DIR = Path.home() / ".local/state/vpn-manager"
KEEPER_CFG = "incy-xray-active.json"
PROBE_CFG = "incy-probe-active.json"
BIN_FILE = STATE_DIR / "incy-xray.bin"
ASSET_FILE = STATE_DIR / "incy-xray.assets"


def stage_xray_run(cfg: dict, slot: str) -> None:
    if slot not in (KEEPER_CFG, PROBE_CFG):
        raise ValueError(f"bad incy config slot: {slot!r}")
    xray = incy_xray()
    if not xray.is_file():
        raise OSError("INCY xray binary missing")
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    fsutil.write_json_atomic(STATE_DIR / slot, cfg)
    _write_text_atomic(BIN_FILE, str(xray))
    if ad := asset_dir():
        _write_text_atomic(ASSET_FILE, str(ad))
    else:
        ASSET_FILE.unlink(missing_ok=True)


def _write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        os.write(fd, text.encode())
        os.close(fd)
        fd = -1
        tmp_path = Path(tmp)
        tmp_path.chmod(0o600)
        tmp_path.replace(path)
    finally:
        if fd >= 0:
            os.close(fd)
        Path(tmp).unlink(missing_ok=True)


def popen_xray(cfg: dict, slot: str) -> subprocess.Popen[bytes]:
    stage_xray_run(cfg, slot)
    return subprocess.Popen(
        ["sudo", "-n", HELPER, "incy-run", slot],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
