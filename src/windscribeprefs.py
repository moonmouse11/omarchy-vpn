"""Validated persistent Windscribe connection preferences."""

WINDSCRIBE_PROTOCOLS = ("automatic", "wireguard", "udp", "tcp", "stealth", "wstunnel")


def normalize_protocol(value: object) -> str:
    return value if isinstance(value, str) and value in WINDSCRIBE_PROTOCOLS else "automatic"


def normalize_port(value: object) -> str:
    if not isinstance(value, str) or not value.isascii() or not value.isdigit():
        return ""
    port = int(value)
    return str(port) if 1 <= port <= 65535 else ""
