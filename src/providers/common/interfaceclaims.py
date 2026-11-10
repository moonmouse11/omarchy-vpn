"""Exact runtime tunnel ownership shared between providers.

Claims prevent a vendor-created interface from also appearing as another
provider's orphan profile. They never infer ownership from an interface name.
"""

import json
from pathlib import Path

import fsutil

CLAIM_FILE = Path.home() / ".cache/vpn-manager/interface-claims.json"
SYS_NET = Path("/sys/class/net")
BOOT_ID_FILE = Path("/proc/sys/kernel/random/boot_id")


def _identity(interface: object) -> tuple[str, int, str] | None:
    if not isinstance(interface, str) or not interface or Path(interface).name != interface:
        return None
    try:
        inode = (SYS_NET / interface).stat().st_ino
        boot_id = BOOT_ID_FILE.read_text().strip()
    except OSError:
        return None
    return (interface, inode, boot_id) if boot_id else None


def _read() -> dict[str, tuple[str, int, str]]:
    try:
        data = json.loads(CLAIM_FILE.read_text())
    except OSError, ValueError, TypeError:
        return {}
    if not isinstance(data, dict):
        return {}
    claims: dict[str, tuple[str, int, str]] = {}
    for provider, value in data.items():
        if not isinstance(provider, str) or not isinstance(value, list) or len(value) != 3:
            continue
        identity = _identity(value[0])
        if identity is not None and identity[1:] == tuple(value[1:]):
            claims[provider] = identity
    return claims


def claim(provider: str, interface: str) -> None:
    identity = _identity(interface)
    if identity is None:
        return
    claims = _read()
    claims[provider] = identity
    fsutil.write_json_atomic(CLAIM_FILE, claims)


def release(provider: str) -> None:
    claims = _read()
    if provider not in claims:
        return
    del claims[provider]
    fsutil.write_json_atomic(CLAIM_FILE, claims)


def get(provider: str) -> str | None:
    identity = _read().get(provider)
    return identity[0] if identity is not None else None


def claimed_by_others(provider: str) -> set[str]:
    return {identity[0] for owner, identity in _read().items() if owner != provider}
