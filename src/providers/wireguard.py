"""Shim — implementation in providers.kernel (no star-import: run_helper must stay patchable)."""

import shutil

from providers.common.helper import run_helper
from providers.kernel.wireguard import (
    AMNEZIA_DIR,
    AWG_INSTALL_HINT,
    WG_DIR,
    AmneziaWGProvider,
    WireGuardProvider,
    _active_interfaces,
    _awg_interface_names,
    _has_dns_directive,
    _net_iface_exists,
    _quick_connect_error,
    _run,
    _runtime_endpoint,
    wg_endpoint,
)

__all__ = [
    "AMNEZIA_DIR",
    "AWG_INSTALL_HINT",
    "WG_DIR",
    "AmneziaWGProvider",
    "WireGuardProvider",
    "_active_interfaces",
    "_awg_interface_names",
    "_has_dns_directive",
    "_net_iface_exists",
    "_quick_connect_error",
    "_run",
    "_runtime_endpoint",
    "run_helper",
    "shutil",
    "wg_endpoint",
]
