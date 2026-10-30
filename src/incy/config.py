"""Runnable xray config for an INCY server (via shared happ/ merge)."""

from __future__ import annotations

import copy

import config
from happ.servers import build_runtime_config, match_server
from incy.subscriptions import all_catalog_entries, fetch_servers

TUN_IFACE = "incy-xray"


def _patch_tun(cfg: dict) -> dict:
    out = copy.deepcopy(cfg)
    for inbound in out.get("inbounds") or []:
        if inbound.get("protocol") == "tun":
            inbound.setdefault("settings", {})["name"] = TUN_IFACE
    return out


def resolve_config(
    name: str,
    *,
    provider_id: str | None = None,
    allow_fetch: bool = True,
) -> dict | None:
    tunnel_dns = config.load_config().dns_mode == "tunnel"
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
    merged = build_runtime_config(entry["config"], tunnel_dns=tunnel_dns)
    return _patch_tun(merged)
