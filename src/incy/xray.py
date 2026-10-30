"""INCY-bundled xray helpers."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from incy.paths import incy_xray as _incy_xray
from incy.paths import install_root

GEO_DIRS = (
    Path.home() / ".local/share/incy/geo_trimmed",
    Path.home() / ".local/share/incy/geo",
)

XRAY_TEST_TIMEOUT = 10
XRAY_ERROR_PREFIX = "main: failed to load config files:"
XRAY_ERROR_MAXLEN = 240


def _geo_dirs() -> tuple[Path, ...]:
    dirs: list[Path] = list(GEO_DIRS)
    if root := install_root():
        dirs.append(root / "lib/app/resources")
    return tuple(dirs)


def asset_dir() -> Path | None:
    for base in _geo_dirs():
        try:
            for geo in sorted(base.glob("**/geoip.dat")):
                return geo.parent
        except OSError:
            continue
    return None


def config_error(cfg: dict) -> str | None:
    xray = _incy_xray()
    if not xray.is_file():
        return "INCY xray binary missing"
    env = {**os.environ}
    if ad := asset_dir():
        env["XRAY_LOCATION_ASSET"] = str(ad)
    try:
        result = subprocess.run(
            [str(xray), "run", "-test", "-c", "stdin:"],
            input=json.dumps(cfg),
            capture_output=True,
            text=True,
            env=env,
            timeout=XRAY_TEST_TIMEOUT,
            check=False,
        )
    except OSError, subprocess.TimeoutExpired:
        return None
    if result.returncode == 0:
        return None
    lines = (result.stdout + result.stderr).strip().splitlines()
    for line in reversed(lines):
        if XRAY_ERROR_PREFIX in line:
            msg = line.split(XRAY_ERROR_PREFIX, 1)[-1].strip()
            return msg[:XRAY_ERROR_MAXLEN]
    tail = lines[-1] if lines else "xray rejected the config"
    return tail[:XRAY_ERROR_MAXLEN]
