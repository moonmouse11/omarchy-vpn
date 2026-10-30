"""Tools menu actions, import/profile, settings launcher."""

import contextlib
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import killswitch
import quickconnect
import settings_tui
from app.checks import run_check
from app.helpers import notify, refresh_bar
from app.provider_lookup import provider_named as _provider_named
from app.registry import _provider_pool, active_connections
from app.status import _killswitch_unsupported
from app.switch import _killswitch_toggle, _sync_ipv6_guard, sync_ipv6_boot
from happ.constants import MANAGER
from providers.base import ActionResult


def _patched(name: str, local):
    import vpn_manager as vm  # noqa: PLC0415

    remote = getattr(vm, name, None)
    if remote is not None and remote is not local:
        return remote
    return local


IMPORT_KINDS = {
    "WireGuard": "file",
    "AmneziaWG": "file",
    "OpenVPN": "file",
    "NetworkManager": "file",
    "VLESS": "key",
    "Shadowsocks": "key",
}
IMPORT_EXTENSIONS = {"OpenVPN": "ovpn conf", "NetworkManager": "conf ovpn"}
MANAGED_PROVIDERS = (
    "WireGuard",
    "AmneziaWG",
    "NetworkManager",
    "OpenVPN",
    "VLESS",
    "Shadowsocks",
)
AUTOSTART_PROVIDERS = ("WireGuard", "AmneziaWG", "NetworkManager", "OpenVPN")
FILE_SELECT_TIMEOUT = 660
CACHE_DIR = Path.home() / ".cache/vpn-manager"
SETTINGS_WINDOW_CLASS = "TUI.float"
SETTINGS_WINDOW_TITLE = "VPN Settings"
KILLSWITCH_ICON = settings_tui.KILLSWITCH_ICON


def refresh_all_menu() -> ActionResult:
    subprocess.Popen(
        [sys.executable, str(MANAGER), "--update-subs-force"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return ActionResult(True, "Refresh started in the background")


def clear_caches_menu() -> ActionResult:
    import vpn_manager as vm  # noqa: PLC0415 — tests patch vpn_manager.CACHE_DIR

    cache_dir = vm.CACHE_DIR
    removed = 0
    if cache_dir.is_dir():
        for f in cache_dir.glob("*.json"):
            if f.name.startswith("subscription-"):
                continue
            with contextlib.suppress(OSError):
                f.unlink()
                removed += 1
    return ActionResult(True, f"Cache cleared ({removed} files) — rebuilt automatically")


def _settings_tool_keys() -> list[tuple[str, str]]:
    return [(key, label) for key, label, _fn in TOOLS if key != "settings"] + [
        ("killswitch", f"{KILLSWITCH_ICON} Killswitch")
    ]


def settings_menu() -> ActionResult:
    terminal = [
        "xdg-terminal-exec",
        f"--app-id={SETTINGS_WINDOW_CLASS}",
        f"--title={SETTINGS_WINDOW_TITLE}",
        "-e",
        sys.executable,
        str(MANAGER),
        "--settings",
    ]
    if shutil.which("uwsm-app"):
        terminal = ["uwsm-app", "--", *terminal]
    if shutil.which("omarchy-launch-or-focus"):
        cmd = ["omarchy-launch-or-focus", SETTINGS_WINDOW_TITLE, shlex.join(terminal)]
    else:
        cmd = terminal
    try:
        subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True
        )
    except OSError:
        return ActionResult(
            False, "No terminal launcher (xdg-terminal-exec) — run vpn_manager.py --settings"
        )
    return ActionResult(True, "")


def run_settings_window() -> None:
    if settings_tui.main([p.name for p in _provider_pool()], _settings_tool_keys()):
        _sync_ipv6_guard()
        boot = sync_ipv6_boot()
        notify("VPN", "Settings saved" + ("" if boot.success else f"\n{boot.message}"))
        refresh_bar()


TOOLS = [
    ("dns_leak_test", "🔍 DNS Leak Test", lambda: run_check("dns")),
    ("ip_info", "ℹ️ IP Info", lambda: run_check("ip")),
    ("speed_test", "⚡ Speed Test", lambda: run_check("speed", "all")),
    ("refresh_all", "🔄 Refresh All", refresh_all_menu),
    ("clear_caches", "🗑️ Clear Caches", clear_caches_menu),
    ("settings", "⚙️ Settings", settings_menu),
]


def run_tool(key: str) -> ActionResult:
    if key == "killswitch":
        if _killswitch_unsupported(active_connections(providers=list(_provider_pool()))):
            return ActionResult(
                False, "The kill switch is suspended while a NetworkManager VPN is up"
            )
        on = killswitch.is_enabled() or killswitch.mode() in ("happ", "all")
        return _killswitch_toggle(not on)
    import vpn_manager as vm  # noqa: PLC0415 — tests patch vpn_manager.TOOLS

    return next(fn for k, _label, fn in vm.TOOLS if k == key)()


def run_import(provider_name: str, source: str | None = None) -> ActionResult:
    provider = _provider_named(provider_name)
    if provider is None or provider_name not in IMPORT_KINDS:
        return ActionResult(False, f"{provider_name}: import not supported")
    if source == "-":
        source = sys.stdin.read()
    elif source is None:
        cmd = [
            "omarchy-file-select",
            "--title",
            f"Import {provider_name} config",
            "--extensions",
            IMPORT_EXTENSIONS.get(provider_name, "conf"),
        ]
        try:
            picked = subprocess.run(
                cmd, check=False, capture_output=True, text=True, timeout=FILE_SELECT_TIMEOUT
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            return ActionResult(False, f"File chooser failed: {e}")
        if picked.returncode == 1:
            return ActionResult(True, "")
        if picked.returncode != 0:
            return ActionResult(False, f"File chooser failed: {picked.stderr.strip()}")
        source = picked.stdout.splitlines()[0] if picked.stdout.strip() else ""
    source = source.strip()
    if not source:
        return ActionResult(False, "Nothing to import")
    return provider.import_config(source)


def run_profile_action(action: str, provider_name: str, name: str) -> ActionResult:
    provider = _provider_named(provider_name)
    if provider is None or provider_name not in MANAGED_PROVIDERS:
        return ActionResult(False, f"{provider_name}: profiles can't be managed here")
    conn = next((c for c in provider.connections() if c.name == name), None)
    if conn is None:
        return ActionResult(False, f"{provider_name}: {name} not found")
    if action == "autostart":
        if provider_name not in AUTOSTART_PROVIDERS:
            return ActionResult(False, f"{provider_name}: autostart not supported")
        result = provider.toggle_autostart(conn)
        if result.success:
            boot = _patched("sync_ipv6_boot", sync_ipv6_boot)()
            if not boot.success:
                return ActionResult(True, f"{result.message} — {boot.message}")
        return result
    result = provider.delete_config(conn)
    if result.success:
        with contextlib.suppress(OSError):
            quickconnect.forget(provider_name, name, conn.subscription_id or "")
    return result
