"""Pure parsing for supported ``windscribe-cli status`` contracts."""

import re
from dataclasses import dataclass

_CONNECTION_ANNOTATION = re.compile(
    r"\((?:checking the connection|network interference detected)\)|\[network interference\]",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class WindscribeStatus:
    recognized: bool = False
    internet: str = "unknown"
    login_state: str = "unknown"
    login_error: str = ""
    connection_state: str = "unknown"
    location: str = ""
    checking: bool = False
    network_interference: bool = False
    protocol: str = ""
    port: str = ""
    ip_address: str = ""
    ip_is_vpn: bool = False
    firewall: str = "unknown"
    data_usage: str = ""
    update_version: str = ""


def _fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        label, separator, value = line.partition(":")
        if separator:
            fields[label.strip().lower()] = value.strip()
    return fields


def _state(value: str, names: tuple[str, ...]) -> tuple[str, str]:
    lowered = value.lower()
    for name in names:
        if lowered == name or lowered.startswith(f"{name}:"):
            detail = value.partition(":")[2].strip() if ":" in value else ""
            return name.replace(" ", "_"), detail
    if lowered.startswith("error"):
        return "error", value.partition(":")[2].strip()
    return "unknown", ""


def _connection(value: str) -> tuple[str, str, bool, bool]:
    checking = "(checking the connection)" in value.lower() or value.lstrip().startswith("*")
    interference = (
        "(network interference detected)" in value.lower()
        or "[network interference]" in value.lower()
    )
    clean = _CONNECTION_ANNOTATION.sub("", value).lstrip("* ").strip()
    lowered = clean.lower()
    for state in ("connected", "connecting"):
        prefix = f"{state} to "
        if lowered.startswith(prefix):
            return state, clean[len(prefix) :].strip(), checking, interference
    state, detail = _state(clean, ("connected", "connecting", "disconnecting", "disconnected"))
    return state, detail, checking, interference


def _protocol(value: str) -> tuple[str, str]:
    name, separator, port = value.partition(":")
    return name.strip().lower(), port.strip() if separator else ""


def _firewall(value: str) -> str:
    normalized = value.strip().lower().replace(" ", "_")
    return normalized if normalized in ("off", "on", "always_on") else "unknown"


def parse_status(text: str) -> WindscribeStatus:
    fields = _fields(text)
    login_present = "login state" in fields or "login" in fields
    connection_present = "connect state" in fields or "connection" in fields
    login_value = fields.get("login state", fields.get("login", ""))
    connection_value = fields.get("connect state", fields.get("connection", ""))
    login_state, login_error = _state(login_value, ("logged in", "logged out", "logging in"))
    connection_state, connection_location, checking, interference = _connection(connection_value)
    recognized = (
        (login_present or connection_present)
        and (not login_present or login_state != "unknown")
        and (not connection_present or connection_state != "unknown")
    )
    protocol, port = _protocol(fields.get("protocol", ""))
    vpn_ip = fields.get("vpn ip", "")
    public_ip = fields.get("public ip", "")
    ip_value = fields.get("ip", "")
    if ip_value.lower().endswith(" (vpn)"):
        vpn_ip = ip_value[:-6].strip()
    elif ip_value.lower().endswith(" (public)"):
        public_ip = ip_value[:-9].strip()
    update = fields.get("update available", fields.get("update", ""))
    if update.lower().endswith(" available"):
        update = update[: -len(" available")].strip()
    return WindscribeStatus(
        recognized=recognized,
        internet=fields.get("internet connectivity", fields.get("internet", "unknown")).lower(),
        login_state=login_state,
        login_error=login_error,
        connection_state=connection_state,
        location=connection_location or fields.get("location", ""),
        checking=checking,
        network_interference=interference,
        protocol=protocol,
        port=port,
        ip_address=vpn_ip or public_ip,
        ip_is_vpn=bool(vpn_ip),
        firewall=_firewall(fields.get("firewall state", fields.get("firewall", ""))),
        data_usage=fields.get("data usage", ""),
        update_version=update,
    )
