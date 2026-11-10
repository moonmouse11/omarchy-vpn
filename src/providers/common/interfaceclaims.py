"""Exact runtime tunnel ownership shared between providers.

Claims prevent a vendor-created interface from also appearing as another
provider's orphan profile. They never infer ownership from an interface name.
"""

import json
from pathlib import Path

import fsutil

CLAIM_FILE = Path.home() / ".cache/vpn-manager/interface-claims.json"
SYS_NET = Path("/sys/class/net")


def _valid_interface(interface: object) -> str | None:
    if not isinstance(interface, str) or not interface or Path(interface).name != interface:
        return None
    return interface if (SYS_NET / interface).exists() else None


def _read() -> dict[str, str]:
    try:
        data = json.loads(CLAIM_FILE.read_text())
    except OSError, ValueError, TypeError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        provider: interface
        for provider, value in data.items()
        if isinstance(provider, str) and (interface := _valid_interface(value)) is not None
    }


def claim(provider: str, interface: str) -> None:
    if _valid_interface(interface) is None:
        return
    claims = _read()
    claims[provider] = interface
    fsutil.write_json_atomic(CLAIM_FILE, claims)


def release(provider: str) -> None:
    claims = _read()
    if provider not in claims:
        return
    del claims[provider]
    fsutil.write_json_atomic(CLAIM_FILE, claims)


def get(provider: str) -> str | None:
    return _read().get(provider)


def claimed_by_others(provider: str) -> set[str]:
    return {interface for owner, interface in _read().items() if owner != provider}
