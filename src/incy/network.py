"""INCY broker socket policy; the core never needs network capabilities."""

from __future__ import annotations

import copy
import re
import socket

BROKER_MARK = 0x6B74
PROXY_PRIORITY = 6


def prepare_config(config: dict) -> dict:
    from happ.constants import (  # noqa: PLC0415 — root broker never imports app code
        KILLSWITCH_MARK,
        NON_PROXY_PROTOCOLS,
    )

    result = copy.deepcopy(config)
    has_ss = any(o.get("protocol") == "shadowsocks" for o in result.get("outbounds", []))
    for inbound in result.get("inbounds", []):
        if inbound.get("protocol") != "tun":
            continue
        if has_ss:
            # shortcut: SS + TUN sniffing stalls in the tested FD path; restore after investigation.
            inbound.setdefault("sniffing", {})["enabled"] = False
        settings = inbound.setdefault("settings", {})
        for field in (
            "gateway",
            "autoSystemRoutingTable",
            "autoOutboundsInterface",
            "autoSystemDnsToGateway",
        ):
            settings.pop(field, None)
    for outbound in result.get("outbounds", []):
        sockopt = outbound.setdefault("streamSettings", {}).setdefault("sockopt", {})
        proxy = sockopt.pop("mark", None) == KILLSWITCH_MARK and (
            outbound.get("protocol") not in NON_PROXY_PROTOCOLS
            or outbound.get("tag") == "dns-direct"
        )
        sockopt.pop("interface", None)
        if proxy:
            # Endpoint hostnames must use the tagged bootstrap resolver, not libc through the TUN.
            sockopt["domainStrategy"] = "UseIPv4"
        custom = sockopt.setdefault("customSockopt", [])
        if not isinstance(custom, list):
            raise ValueError("INCY customSockopt must be a list")
        # Last option wins: subscription-provided priority cannot turn direct into proxy.
        custom.append(
            {"level": "1", "opt": "12", "value": str(PROXY_PRIORITY if proxy else 0), "type": "int"}
        )
    return result


def protect_socket(sock: socket.socket, uplink: str) -> None:
    """Fixed privileged operation, called only after broker descriptor validation."""
    if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,14}", uplink) is None:
        raise ValueError("Invalid INCY uplink interface")
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, uplink.encode() + b"\0")
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, BROKER_MARK)
