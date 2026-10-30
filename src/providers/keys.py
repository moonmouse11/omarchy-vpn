"""Shim — implementation in providers.happd.keys (patchable module attrs for tests)."""

import json
import subprocess
import time

from providers.common.types import ActionResult, VPNConnection
from providers.happd.keys import (
    IFACES,
    KEEPER_STATE_DIR,
    LABELS,
    METHODS,
    STORE,
    XRAY_TIMEOUT,
    KeysProvider,
    _build_xray_config,
    _find_server,
    _key_fields,
    _load_servers,
    _new_uid,
    _save_servers,
    _ss_outbound,
    _vless_outbound,
    add_server,
    parse_key,
    parse_ss_key,
    parse_vless_key,
    run_keeper,
)

__all__ = [
    "IFACES",
    "KEEPER_STATE_DIR",
    "LABELS",
    "METHODS",
    "STORE",
    "XRAY_TIMEOUT",
    "ActionResult",
    "KeysProvider",
    "VPNConnection",
    "_build_xray_config",
    "_find_server",
    "_key_fields",
    "_load_servers",
    "_new_uid",
    "_save_servers",
    "_ss_outbound",
    "_vless_outbound",
    "add_server",
    "json",
    "parse_key",
    "parse_ss_key",
    "parse_vless_key",
    "run_keeper",
    "subprocess",
    "time",
]
