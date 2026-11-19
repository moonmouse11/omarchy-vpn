"""User configuration: ~/.config/vpn-manager/config.json.

All keys optional; missing file means defaults:

{
  "providers": {"openvpn": false},      // hide providers from menu/status
  "killswitch_mode": "all",             // "off" | "happ" | "all" — auto-manage killswitch
  "killswitch_lockdown": true,          // keep blocking while no VPN is up
  "exit_ip": {"enabled": true, "max_age_seconds": 600},
  "ip_sources": {"abuseipdb": {"api_key": "secret"}},  // IP source configurations
  "tools_visible": {"dns_leak_test": false},          // hide tools from menu
  "speed_test_urls": ["http://10.0.0.5/100MB.bin"],    // extra Speed Test targets
  "dns_mode": "tunnel",                 // "tunnel" | "subscription": who routes xray's DNS
  "dns_autotest": false,                // run the DNS leak test in the background after a connect
  "panel_key_hints": true,              // the key line at the bottom of the bar panel
  "locations_layout": "tree",           // "tree" | "tabs" | "sidebar": protocols in the app window
  "ipv6_guard": true,                   // IPv6 off while a VPN is up and before autostart at boot
  "windscribe": {"protocol": "automatic", "port": ""}
}
"""

import contextlib
import fcntl
import json
import os
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path

import fsutil
from windscribeprefs import normalize_port, normalize_protocol

CONFIG_PATH = Path.home() / ".config" / "vpn-manager" / "config.json"
DNS_MODES = ("tunnel", "subscription")
LOCATIONS_LAYOUTS = ("tree", "tabs", "sidebar")


@dataclass
class Config:
    providers: dict[str, bool] = field(default_factory=dict)
    killswitch_mode: str = "off"  # "off" | "happ" | "all"
    # Lockdown: the kill switch keeps blocking while no VPN is up (until it is
    # turned off); False drops the rules on disconnect, the next connect sets them
    killswitch_lockdown: bool = True
    exit_ip_enabled: bool = True
    exit_ip_max_age: int = 600
    ip_sources: dict[str, dict] = field(default_factory=dict)
    tools_visible: dict[str, bool] = field(default_factory=dict)
    speed_test_urls: list[str] = field(default_factory=list)
    # "tunnel": xray's DNS always follows the tunnel, overriding subscription
    # rules that pin resolvers direct (a leak); "subscription": as shipped
    dns_mode: str = "tunnel"
    # off by default: it sends ~30 lookups to bash.ws after every connect
    dns_autotest: bool = False
    panel_key_hints: bool = True
    locations_layout: str = "tree"
    # none of the providers tunnel IPv6: off while a VPN is up, and at boot
    # before an autostarted WireGuard tunnel (omarchy-vpn-helper ipv6-boot)
    ipv6_guard: bool = True
    windscribe_protocol: str = "automatic"
    windscribe_port: str = ""

    def provider_visible(self, name: str) -> bool:
        return self.providers.get(name.lower(), True)

    def tool_visible(self, key: str) -> bool:
        return self.tools_visible.get(key, True)


def _bool(value: object, default: bool) -> bool:
    return value if isinstance(value, bool) else default


def load_config() -> Config:
    cfg = Config()
    try:
        raw = json.loads(CONFIG_PATH.read_text())
    except OSError, json.JSONDecodeError:
        return cfg
    if not isinstance(raw, dict):
        return cfg

    providers = raw.get("providers")
    if isinstance(providers, dict):
        cfg.providers = {str(k).lower(): v for k, v in providers.items() if isinstance(v, bool)}

    if raw.get("killswitch_mode") in ("off", "happ", "all"):
        cfg.killswitch_mode = raw["killswitch_mode"]

    if "killswitch_lockdown" in raw:
        cfg.killswitch_lockdown = _bool(raw["killswitch_lockdown"], cfg.killswitch_lockdown)

    exit_ip = raw.get("exit_ip")
    if isinstance(exit_ip, dict):
        cfg.exit_ip_enabled = bool(exit_ip.get("enabled", True))
        with contextlib.suppress(TypeError, ValueError):
            cfg.exit_ip_max_age = max(60, int(exit_ip.get("max_age_seconds", 600)))

    ip_sources = raw.get("ip_sources")
    if isinstance(ip_sources, dict):
        cfg.ip_sources = {str(k): v for k, v in ip_sources.items() if isinstance(v, dict)}

    tools_visible = raw.get("tools_visible")
    if isinstance(tools_visible, dict):
        cfg.tools_visible = {str(k): v for k, v in tools_visible.items() if isinstance(v, bool)}

    speed_test_urls = raw.get("speed_test_urls")
    if isinstance(speed_test_urls, list):
        cfg.speed_test_urls = [u for u in speed_test_urls if isinstance(u, str) and u]

    if raw.get("dns_mode") in DNS_MODES:
        cfg.dns_mode = raw["dns_mode"]

    if "dns_autotest" in raw:
        cfg.dns_autotest = _bool(raw["dns_autotest"], cfg.dns_autotest)
    if "panel_key_hints" in raw:
        cfg.panel_key_hints = _bool(raw["panel_key_hints"], cfg.panel_key_hints)
    if raw.get("locations_layout") in LOCATIONS_LAYOUTS:
        cfg.locations_layout = raw["locations_layout"]
    if "ipv6_guard" in raw:
        cfg.ipv6_guard = _bool(raw["ipv6_guard"], cfg.ipv6_guard)
    windscribe = raw.get("windscribe")
    if isinstance(windscribe, dict):
        cfg.windscribe_protocol = normalize_protocol(windscribe.get("protocol"))
        if cfg.windscribe_protocol != "automatic":
            cfg.windscribe_port = normalize_port(windscribe.get("port"))
    return cfg


@contextlib.contextmanager
def _config_lock() -> Iterator[None]:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(CONFIG_PATH.with_suffix(".lock"), os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def save_config(cfg: Config) -> None:
    """Deliberately replace the complete configuration, serialized with patch saves."""
    with _config_lock():
        _write_config(cfg)


def _merge_changes(previous: dict, updated: dict, current: dict) -> dict:
    merged = current.copy()
    for key in previous.keys() | updated.keys():
        if key not in updated:
            merged.pop(key, None)
        elif key not in previous or previous[key] != updated[key]:
            before, after, latest = previous.get(key, {}), updated[key], current.get(key, {})
            if isinstance(before, dict) and isinstance(after, dict) and isinstance(latest, dict):
                merged[key] = _merge_changes(before, after, latest)
            else:
                merged[key] = after
    return merged


def save_config_changes(previous: Config, updated: Config) -> Config:
    """Apply only edited fields/keys to the latest configuration under a shared lock."""
    with _config_lock():
        merged = Config(**_merge_changes(asdict(previous), asdict(updated), asdict(load_config())))
        _write_config(merged)
        return merged


def _write_config(cfg: Config) -> None:
    raw = {
        "providers": cfg.providers,
        "killswitch_mode": cfg.killswitch_mode,
        "killswitch_lockdown": cfg.killswitch_lockdown,
        "exit_ip": {
            "enabled": cfg.exit_ip_enabled,
            "max_age_seconds": cfg.exit_ip_max_age,
        },
        "ip_sources": cfg.ip_sources,
        "tools_visible": cfg.tools_visible,
        "speed_test_urls": cfg.speed_test_urls,
        "dns_mode": cfg.dns_mode,
        "dns_autotest": cfg.dns_autotest,
        "panel_key_hints": cfg.panel_key_hints,
        "locations_layout": cfg.locations_layout,
        "ipv6_guard": cfg.ipv6_guard,
        "windscribe": {
            "protocol": normalize_protocol(cfg.windscribe_protocol),
            "port": (
                normalize_port(cfg.windscribe_port)
                if normalize_protocol(cfg.windscribe_protocol) != "automatic"
                else ""
            ),
        },
    }
    fsutil.write_json_atomic(CONFIG_PATH, raw, indent=2)
