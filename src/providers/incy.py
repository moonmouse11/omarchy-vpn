"""Shim — implementation in providers.happd.incy (patchable attrs for tests)."""

import subprocess
import time
from pathlib import Path

from incy.keeper import KEEPER_STATE, run_keeper
from incy.paths import incy_bin, incy_installed, incy_library
from providers.happd.incy import (
    IFACE_PREFIX,
    INCY_CONFIG,
    INCY_SOCK,
    IncyProvider,
    app_connected,
    incy_server_groups,
)

INCY_DB = Path.home() / ".local/share/incy/incy.db"

__all__ = [
    "IFACE_PREFIX",
    "INCY_CONFIG",
    "INCY_DB",
    "INCY_SOCK",
    "KEEPER_STATE",
    "IncyProvider",
    "app_connected",
    "incy_bin",
    "incy_installed",
    "incy_library",
    "incy_server_groups",
    "run_keeper",
    "subprocess",
    "time",
]
