"""System DNS discovery shared with the fixed root helper; stdlib dependencies only."""

import ipaddress
import re
import subprocess
from pathlib import Path

_RESOLVECTL_ADDR = re.compile(r"(?<![\w:.])([0-9A-Fa-f:.]+)(?:%\S+)?(?:#\S+)?")


def _ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _configured(path: Path) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return []
    found = []
    for line in lines:
        parts = line.split()
        if (
            len(parts) >= 2
            and parts[0] == "nameserver"
            and (addr := _ip(parts[1].split("%")[0])) is not None
        ):
            found.append(addr)
    return found


def _resolved() -> list[str]:
    try:
        out = subprocess.run(
            ["/usr/bin/resolvectl", "dns"], capture_output=True, text=True, timeout=5, check=False
        ).stdout
    except OSError, subprocess.SubprocessError:
        return []
    found = []
    for line in out.splitlines():
        servers = line if line[:1].isspace() else line.partition(":")[2]
        for token in servers.split():
            match = _RESOLVECTL_ADDR.fullmatch(token)
            addr = _ip(match.group(1)) if match else None
            if addr is not None and not addr.is_loopback:
                found.append(str(addr))
    return found


def bootstrap_resolvers(path: Path = Path("/etc/resolv.conf")) -> list[str]:
    """Port-53 bootstrap must not silently bypass a local proxy or required TLS."""
    loopback = [str(addr) for addr in _configured(path) if addr.is_loopback]
    if any(addr not in ("127.0.0.53", "127.0.0.54") for addr in loopback):
        raise OSError("Local DNS proxy bootstrap is unsupported; DNS settings were not changed")
    if loopback:
        try:
            result = subprocess.run(
                ["/usr/bin/resolvectl", "dnsovertls"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise OSError("Cannot verify DNS transport; refusing plaintext bootstrap") from error
        modes = [line.partition(":")[2].strip() for line in result.stdout.splitlines()]
        modes = [mode for mode in modes if mode]
        if (
            result.returncode
            or not modes
            or any(mode not in ("no", "opportunistic") for mode in modes)
        ):
            raise OSError("Required or unknown DNS-over-TLS policy; refusing plaintext bootstrap")
    return system_resolvers(path)


def system_resolvers(path: Path = Path("/etc/resolv.conf")) -> list[str]:
    """Return numeric non-loopback upstreams, expanding a systemd-resolved stub."""
    configured = _configured(path)
    found = [str(addr) for addr in configured if not addr.is_loopback]
    if any(addr.is_loopback for addr in configured):
        found.extend(_resolved())
    return list(dict.fromkeys(found))
