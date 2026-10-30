"""Happ subscription metadata — facade for backward compatibility.

Tests and legacy imports patch attributes on this module (`subprocess`,
`urllib.request`, `ROUTE_TABLE`, …). Implementation lives in `happ/` and `ping/`.
"""

import socket
import subprocess
import urllib

import lazyimports
from happ import *
from happ.constants import (
    CAPTURED_PROVIDERS,
    CATCH_ALL_RULE,
    DEFAULT_INBOUNDS,
    DNS_BOOTSTRAP_FALLBACK,
    DNS_BOOTSTRAP_TAG,
    HAPP_GUI_BIN,
    HAPP_VERSION_FALLBACK,
    HEADERS_FILE,
    KILLSWITCH_MARK,
    LOCAL_ROUTING_RULES,
    LOG_FILE,
    MACHINE_ID_FILES,
    MANAGER,
    NON_PROXY_PROTOCOLS,
    PROVIDERS_CACHE,
    ROUTING_FILE,
    SUB_CACHE_DIR,
    SUB_MAX_AGE,
    SUBS_REFRESH_RETRY,
    XRAY_CONFIGS,
)
from happ.servers import _outbound_target, _tunnel_target
from happ.subscriptions import (
    _fetch_subscription,
    _parse_providers,
    _subs_refresh_in_progress,
)
from ping import *
from ping.cache import (
    PING_CACHE,
    PING_MAX_AGE,
    read_pings,
)
from ping.cache import (
    read_pings as _read_pings,
)
from ping.measure import ARPHRD_NONE, PING_TIMEOUT, ROUTE_TABLE, SYS_NET
