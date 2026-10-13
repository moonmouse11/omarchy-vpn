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
  "panel_key_hints": true               // the key line at the bottom of the bar panel
}
"""

import contextlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import fsutil

CONFIG_PATH = Path.home() / ".config" / "vpn-manager" / "config.json"
DNS_MODES = ("tunnel", "subscription")


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

    def provider_visible(self, name: str) -> bool:
        return self.providers.get(name.lower(), True)

    def tool_visible(self, key: str) -> bool:
        return self.tools_visible.get(key, True)


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
        cfg.providers = {str(k).lower(): bool(v) for k, v in providers.items()}

    if raw.get("killswitch_mode") in ("off", "happ", "all"):
        cfg.killswitch_mode = raw["killswitch_mode"]

    if "killswitch_lockdown" in raw:
        cfg.killswitch_lockdown = bool(raw["killswitch_lockdown"])

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
        cfg.tools_visible = {str(k): bool(v) for k, v in tools_visible.items()}

    speed_test_urls = raw.get("speed_test_urls")
    if isinstance(speed_test_urls, list):
        cfg.speed_test_urls = [u for u in speed_test_urls if isinstance(u, str) and u]

    if raw.get("dns_mode") in DNS_MODES:
        cfg.dns_mode = raw["dns_mode"]

    if "dns_autotest" in raw:
        cfg.dns_autotest = bool(raw["dns_autotest"])
    if "panel_key_hints" in raw:
        cfg.panel_key_hints = bool(raw["panel_key_hints"])
    return cfg


def save_config(cfg: Config) -> None:
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
    }
    fsutil.write_json_atomic(CONFIG_PATH, raw, indent=2)
