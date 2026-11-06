"""Backward-compatible re-exports — tests patch attributes on this module."""

import os
import subprocess
import time
from pathlib import Path

from providers.common.helper import (
    HELPER,
    HELPER_KINDS,
    _helper_slot,
    read_config_text,
    run_helper,
    terminate_registered_subprocesses,
)
from providers.common.iface import (
    RATE_CACHE,
    _iface_counters,
    human_bytes,
    iface_rate,
    iface_traffic,
    sample_iface_traffic,
)
from providers.common.types import ActionResult, PingTarget, VPNConnection, VPNProvider

__all__ = [
    "HELPER",
    "HELPER_KINDS",
    "RATE_CACHE",
    "ActionResult",
    "Path",
    "PingTarget",
    "VPNConnection",
    "VPNProvider",
    "_helper_slot",
    "_iface_counters",
    "human_bytes",
    "iface_rate",
    "iface_traffic",
    "os",
    "read_config_text",
    "run_helper",
    "sample_iface_traffic",
    "subprocess",
    "terminate_registered_subprocesses",
    "time",
]
