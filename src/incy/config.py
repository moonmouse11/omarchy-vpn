"""Runnable xray config for an INCY server (via shared happ/ merge)."""

from __future__ import annotations

import copy
from typing import Any, cast

import config
from happ.constants import DEFAULT_INBOUNDS
from happ.servers import build_runtime_config, match_server
from incy.subscriptions import all_catalog_entries, fetch_servers

TUN_IFACE = "incy-xray"


def _tun_inbound() -> dict[str, Any]:
    for inbound in DEFAULT_INBOUNDS:
        ib = cast(dict[str, Any], inbound)
        if ib.get("protocol") == "tun":
            tun = copy.deepcopy(ib)
            tun.setdefault("settings", {})["name"] = TUN_IFACE
            return tun
    return {
        "protocol": "tun",
        "settings": {
            "autoOutboundsInterface": "auto",
            "autoSystemRoutingTable": ["0.0.0.0/0"],
            "gateway": ["172.19.0.2/30"],
            "mtu": 1500,
            "name": TUN_IFACE,
            "userLevel": 8,
        },
        "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True, "routeOnly": True},
        "tag": "tun-in",
    }


def build_incy_runtime_config(server_cfg: dict, *, tunnel_dns: bool | None = None) -> dict:
    """Happ-style merge, but TUN-only inbounds — 10808/10809 stay with Happ/Keys."""
    if tunnel_dns is None:
        tunnel_dns = config.load_config().dns_mode == "tunnel"
    merged = build_runtime_config(server_cfg, tunnel_dns=tunnel_dns)
    out = copy.deepcopy(merged)
    out["inbounds"] = [_tun_inbound()]
    return out


def server_endpoints(
    name: str, *, provider_id: str | None = None, allow_fetch: bool = False
) -> list[tuple[str, int]]:
    from happ.servers import server_endpoints_of  # noqa: PLC0415 — shared parser

    cfg = resolve_config(name, provider_id=provider_id, allow_fetch=allow_fetch)
    return server_endpoints_of(cfg) if cfg else []


def resolve_config(
    name: str,
    *,
    provider_id: str | None = None,
    allow_fetch: bool = True,
) -> dict | None:
    tunnel_dns = config.load_config().dns_mode == "tunnel"
    from incy.subscriptions import db_server_raw_config  # noqa: PLC0415 — break cycle

    if raw := db_server_raw_config(name, provider_id):
        return build_incy_runtime_config(raw, tunnel_dns=tunnel_dns)
    catalog = all_catalog_entries(allow_fetch=allow_fetch)
    if provider_id and not any(s["provider_id"] == provider_id for s in catalog):
        servers, _ = fetch_servers(provider_id, force=allow_fetch)
        for cfg in servers:
            catalog.append(
                {
                    "name": str(cfg.get("remarks") or ""),
                    "config": cfg,
                    "provider_id": provider_id,
                    "provider_name": "",
                }
            )
    entry = match_server(name, catalog, provider_id)
    if entry is None:
        return None
    return build_incy_runtime_config(entry["config"], tunnel_dns=tunnel_dns)
