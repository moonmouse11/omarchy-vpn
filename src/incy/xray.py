"""INCY asset discovery and cheap preflight; native startup validates the actual config."""

from __future__ import annotations

from pathlib import Path

from incy.paths import incy_library as _incy_library
from incy.paths import install_root

GEO_DIRS = (
    Path.home() / ".local/share/incy/geo_trimmed",
    Path.home() / ".local/share/incy/geo",
)


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
    if not _incy_library().is_file():
        return "INCY core library missing"
    if not isinstance(cfg, dict):
        return "INCY configuration must be an object"
    # Validate containers we access, not Ferrum's evolving protocol/settings schema.
    for field in ("inbounds", "outbounds"):
        entries = cfg.get(field, [])
        if not isinstance(entries, list):
            return f"INCY {field} must be a list"
        for index, entry in enumerate(entries):
            name = f"{field}[{index}]"
            if not isinstance(entry, dict):
                return f"INCY {name} must be an object"
            for key in ("settings", "sniffing", "streamSettings"):
                if key in entry and not isinstance(entry[key], dict):
                    return f"INCY {name}.{key} must be an object"
            stream = entry.get("streamSettings", {})
            sockopt = stream.get("sockopt", {})
            if not isinstance(sockopt, dict):
                return f"INCY {name}.streamSettings.sockopt must be an object"
            if not isinstance(sockopt.get("customSockopt", []), list):
                return f"INCY {name}.streamSettings.sockopt.customSockopt must be a list"
    return None
