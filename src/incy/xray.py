"""INCY-bundled xray helpers."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

INCY_XRAY = Path("/opt/incy/lib/app/resources/bin/xray")
GEO_DIRS = (
    Path.home() / ".local/share/incy/geo_trimmed",
    Path.home() / ".local/share/incy/geo",
    Path("/opt/incy/lib/app/resources"),
)

XRAY_TEST_TIMEOUT = 10
XRAY_ERROR_PREFIX = "main: failed to load config files:"
XRAY_ERROR_MAXLEN = 240


def asset_dir() -> Path | None:
    for base in GEO_DIRS:
        try:
            for geo in sorted(base.glob("**/geoip.dat")):
                return geo.parent
        except OSError:
            continue
    return None


def config_error(cfg: dict) -> str | None:
    if not INCY_XRAY.is_file():
        return "INCY xray binary missing"
    env = {**os.environ}
    if ad := asset_dir():
        env["XRAY_LOCATION_ASSET"] = str(ad)
    try:
        result = subprocess.run(
            [str(INCY_XRAY), "run", "-test", "-c", "stdin:"],
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
