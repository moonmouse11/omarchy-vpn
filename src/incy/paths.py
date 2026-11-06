"""Resolve INCY install paths (pacman /opt/incy, desktop Exec, PATH, env)."""

from __future__ import annotations

import os
import shutil
from functools import lru_cache
from pathlib import Path

DEFAULT_ROOT = Path("/opt/incy")
DESKTOP = Path.home() / ".local/share/applications/incy.desktop"
LIBRARY_REL = Path("lib/app/resources/bin/libincycore.so")
BIN_REL = Path("bin/incy")


def _root_from_exec(raw: str) -> Path | None:
    line = raw.strip()
    if not line:
        return None
    # Desktop Entry: Exec=/…/opt/incy/bin/incy %u
    exe = line.split()[0] if line.split() else line
    if exe.endswith(("/bin/incy", "\\bin\\incy")):
        return Path(exe).resolve().parent.parent
    return None


def _discover_root() -> Path | None:
    env = os.environ.get("OMARCHY_VPN_INCY_ROOT", "").strip()
    if env:
        root = Path(env)
        if (root / LIBRARY_REL).is_file() or (root / BIN_REL).is_file():
            return root
    if (DEFAULT_ROOT / LIBRARY_REL).is_file() or (DEFAULT_ROOT / BIN_REL).is_file():
        return DEFAULT_ROOT
    which = shutil.which("incy")
    if which:
        root = Path(which).resolve().parent.parent
        if (root / LIBRARY_REL).is_file():
            return root
    try:
        text = DESKTOP.read_text(errors="replace")
    except OSError:
        text = ""
    for raw in text.splitlines():
        if raw.startswith("Exec="):
            desktop_root = _root_from_exec(raw[5:])
            if desktop_root and (desktop_root / LIBRARY_REL).is_file():
                return desktop_root
    return None


@lru_cache(maxsize=1)
def install_root() -> Path | None:
    return _discover_root()


def incy_bin() -> Path:
    root = install_root()
    if root and (root / BIN_REL).is_file():
        return root / BIN_REL
    return DEFAULT_ROOT / BIN_REL


def incy_library() -> Path:
    root = install_root()
    if root and (root / LIBRARY_REL).is_file():
        return root / LIBRARY_REL
    return DEFAULT_ROOT / LIBRARY_REL


def incy_installed() -> bool:
    """Headless connect/ping use the bundled native libraries, never a root binary."""
    library = incy_library()
    return library.is_file() and library.with_name("libxray_ffi.so").is_file()
