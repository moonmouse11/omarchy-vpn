#!/usr/bin/env python3
"""
omarchy-vpn — entry point
Usage:
  vpn_manager.py --status   Output JSON status for the omarchy-shell bar widget
"""

import os  # noqa: F401 — tests patch vpn_manager.os
import shutil  # noqa: F401
import subprocess  # noqa: F401
import sys
import time  # noqa: F401
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# Submodules and stdlib aliases tests patch on the vpn_manager module object
import config  # noqa: F401
import delayping  # noqa: F401
import dnsleak  # noqa: F401
import happmeta  # noqa: F401
import ipinfo  # noqa: F401
import ipv6guard  # noqa: F401
import killswitch  # noqa: F401
import logutil  # noqa: F401
import notifyutil  # noqa: F401
import providers.happd.happ as happ_provider  # noqa: F401
import quickconnect  # noqa: F401
import reputation  # noqa: F401
import settings_tui  # noqa: F401
import speedtest  # noqa: F401
from app.checks import (  # noqa: F401
    CANCELLED,
    CHECK_TITLES,
    DNS_AUTOTEST_SETTLE,
    DNS_AUTOTEST_WAIT,
    DNS_VERDICT_CACHE,
    DNS_VERDICT_MAX_AGE,
    SPEED_TEST_ALL_DURATION,
    SPEED_TEST_ALL_LABEL,
    SPEED_TEST_MAX_URLS,
    CheckCancelled,
    _dns_leak_exit_row,
    _dns_leak_ipv6_row,
    _dns_leak_server_row,
    _dns_leak_verdict_row,
    _emit,
    _failure_hint,
    _name_flag_country,
    _save_dns_verdict,
    request_dns_autotest,
    run_check,
    run_dns_autotest,
)
from app.cli import main
from app.helpers import _collect_ping_targets, notify, refresh_bar  # noqa: F401
from app.ping import (  # noqa: F401
    PING_REFRESH_EVERY,
    _measure,
    _ping_scope_from_args,
    _ping_scope_targets,
    ping_now,
)
from app.registry import PLUGIN_ID, active_connections, visible_providers  # noqa: F401
from app.servers import (  # noqa: F401
    HAPP_NO_HEADERS_TITLE,
    _report,
    _server_row,
    happ_server_groups,
    panel_connect,
    panel_disconnect,
    server_list,
    subscription_report,
)
from app.status import (  # noqa: F401
    LABEL_FIELDS,
    _killswitch_unsupported,
    _switch_in_progress,
    activity_text,
    connecting_text,
    get_status,
    label_fields,
    panel_state,
    request_ip_update,
)
from app.switch import (  # noqa: F401
    CHECK_FLAGS,
    HANDOVER_WAIT,
    OPENVPN_TUN_WAIT,
    PING_LOCK,
    PREEMPT_GRACE,
    PREEMPT_WAIT,
    PROC,
    SWITCH_LOCK,
    SwitchBusy,
    SwitchCancelled,
    _abort_checks,
    _cancel_switch,
    _child_pids,
    _close_dns_hole,
    _disconnect_all,
    _enforce_ipv6_guard,
    _guarded_connect,
    _guarded_disconnect,
    _killswitch_all_targets,
    _killswitch_apply,
    _killswitch_targets,
    _killswitch_toggle,
    _killswitch_wanted,
    _lock_holder,
    _our_process,
    _preempt,
    _release_killswitch_if_unlocked,
    _signal_switch_tree,
    _sync_ipv6_guard,
    _tun_interfaces,
    _wait_for_new_tun,
    disconnect_all,
    guarded_connect,
    guarded_disconnect,
    switch_lock,
    sync_ipv6_boot,
)
from app.tools import (  # noqa: F401
    AUTOSTART_PROVIDERS,
    CACHE_DIR,
    FILE_SELECT_TIMEOUT,
    IMPORT_EXTENSIONS,
    IMPORT_KINDS,
    KILLSWITCH_ICON,
    MANAGED_PROVIDERS,
    SETTINGS_WINDOW_CLASS,
    SETTINGS_WINDOW_TITLE,
    TOOLS,
    _settings_tool_keys,
    clear_caches_menu,
    refresh_all_menu,
    run_import,
    run_profile_action,
    run_settings_window,
    run_tool,
    settings_menu,
)
from providers import ALL_PROVIDERS  # noqa: F401 — tests patch vpn_manager.ALL_PROVIDERS
from providers.base import (  # noqa: F401
    iface_rate,
    iface_traffic,
    run_helper,
    sample_iface_traffic,
    terminate_registered_subprocesses,
)
from providers.common.types import ActionResult, VPNConnection  # noqa: F401

if __name__ == "__main__":
    main()
