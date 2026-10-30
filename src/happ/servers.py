"""Happ subscription metadata (subscriptions, xray runtime config, server registry)."""

import copy
import ipaddress
import json
import urllib.parse
from typing import TYPE_CHECKING

from lazyimports import statistics  # noqa: F401 — registers urllib.request & co. lazily

if TYPE_CHECKING:
    import urllib.request

from happ.constants import *  # noqa: F403  # NOSONAR — shared constants with happmeta/tests
from happ.subscriptions import (
    is_stub_server,
    providers,
)


def _happmeta():
    import happmeta as hm  # noqa: PLC0415 — tests patch happmeta fetch / paths

    return hm


# ── Config merge (subscription config -> runnable xray config) ────────────────


def build_runtime_config(server_cfg: dict, tunnel_dns: bool = True) -> dict:
    """Merge a subscription server config like the Happ GUI does:
    local inbounds, dns-in tag, dns-out outbound, local routing rules,
    drop the subscription's own catch-all (we append our own).

    tunnel_dns (config.json "dns_mode": "tunnel"): pin dns-in to the
    subscription's own catch-all, ahead of its rules — otherwise a rule like
    one provider's {"ip": ["1.1.1.1", ...], "ruleTag": "DNS_DIRECT",
    "outboundTag": "direct"} sends every lookup out the real NIC. Costs the
    provider's split DNS (e.g. Yandex for .ru via geoip:ru) — it then
    resolves through the tunnel too; the traffic itself still splits."""
    cfg = copy.deepcopy(server_cfg)
    cfg["inbounds"] = copy.deepcopy(DEFAULT_INBOUNDS)

    dns = cfg.get("dns") or {}
    dns["tag"] = "dns-in"
    hosts = [h for h, _port in server_endpoints_of(server_cfg) if not _is_ip(h)]
    if hosts:
        bootstrap = {
            "address": _bootstrap_resolver(dns.get("servers") or []),
            "domains": [f"full:{h}" for h in hosts],
            "skipFallback": True,  # nothing else may fall back onto it
            "tag": DNS_BOOTSTRAP_TAG,
        }
        dns["servers"] = [bootstrap, *(dns.get("servers") or [])]
    cfg["dns"] = dns

    outbounds = cfg.get("outbounds") or []
    proxies = [o for o in outbounds if o.get("protocol") not in NON_PROXY_PROTOCOLS]
    for outbound in proxies:
        _set_mark(outbound)
    outbounds.append(_set_mark({"protocol": "freedom", "tag": "dns-direct"}))
    dns_outbound = next((o for o in outbounds if o.get("protocol") == "dns"), None)
    if dns_outbound is None:
        dns_outbound = {"protocol": "dns", "tag": "dns-out"}
        outbounds.append(dns_outbound)
    # Only covers what dns-out forwards itself: non-A/AAAA queries, which
    # xray rejects by default (nonIPQuery) — A/AAAA go to the built-in
    # resolver, routed via "dns-in" (see DNS_BOOTSTRAP_TAG). Kept so a
    # subscription that enables nonIPQuery forwarding still tunnels it.
    # Balancer configs have no "proxy" tag — chain through their first real
    # proxy outbound rather than a tag that resolves to nothing.
    # sockopt.dialerProxy, not the old proxySettings.transportLayer: xray
    # 26.x (Happ 4.5.2) refuses to start on any outbound with proxySettings.
    tags = [o.get("tag") for o in proxies if o.get("tag")]
    if tags:
        via = "proxy" if "proxy" in tags else tags[0]
        sockopt = dns_outbound.setdefault("streamSettings", {}).setdefault("sockopt", {})
        sockopt.setdefault("dialerProxy", via)
    cfg["outbounds"] = outbounds

    rules = list(cfg.get("routing", {}).get("rules", []))
    rules = [
        r for r in rules if not (r.get("outboundTag") == "proxy" and r.get("network") == "tcp,udp")
    ]
    dns_rules = []
    if tunnel_dns:
        dns_rules = [{"inboundTag": ["dns-in"], **_tunnel_target(rules, outbounds)}]
    cfg.setdefault("routing", {})["rules"] = [
        *LOCAL_ROUTING_RULES,
        *dns_rules,
        *rules,
        CATCH_ALL_RULE,
    ]
    for balancer in cfg["routing"].get("balancers") or []:
        _normalize_balancer(balancer)
    cfg["log"] = {"loglevel": "info"}
    return cfg


def _normalize_balancer(balancer: dict) -> None:
    """Move a strategy written as `"settings": {"type": ...}` into `"strategy"`.

    xray reads a balancer's strategy only from "strategy" and ignores an
    unknown "settings" key without a word — so a subscription balancer
    meant to be leastPing silently ran as random (seen live: one of 129
    balancers across 5 subscriptions). A real "strategy" always wins."""
    settings = balancer.get("settings")
    if "strategy" in balancer or not isinstance(settings, dict) or "type" not in settings:
        return
    rest = dict(settings)
    strategy = {"type": rest.pop("type")}
    if rest:
        strategy["settings"] = rest
    balancer["strategy"] = strategy
    del balancer["settings"]


_CATCH_ALL_KEYS = {"type", "network", "ruleTag", "outboundTag", "balancerTag"}
_TARGET_KEYS = ("balancerTag", "outboundTag")


def _tunnel_target(rules: list[dict], outbounds: list[dict]) -> dict:
    """Where app traffic goes by default: the subscription's last pure
    catch-all rule (no matchers but network — an inboundTag-restricted one
    like {"inboundTag": ["socks", "http"]} never sees dns-in/tun-in), else
    our CATCH_ALL_RULE. Never a freedom outbound: a direct-by-default
    (whitelist-style) subscription would take DNS out the real NIC with
    it — the first real proxy outbound carries DNS instead."""
    target = {"outboundTag": CATCH_ALL_RULE["outboundTag"]}
    for rule in rules:
        if set(rule) <= _CATCH_ALL_KEYS and any(k in rule for k in _TARGET_KEYS):
            target = {k: rule[k] for k in _TARGET_KEYS if k in rule}
    freedom = {o.get("tag") for o in outbounds if o.get("protocol") == "freedom"}
    if target.get("outboundTag") in freedom:
        proxy = next(
            (
                o["tag"]
                for o in outbounds
                if o.get("tag") and o.get("protocol") not in NON_PROXY_PROTOCOLS
            ),
            None,
        )
        if proxy:
            return {"outboundTag": proxy}
    return target


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _bootstrap_resolver(servers: list) -> str:
    """The subscription's first resolver usable for bootstrap: unrestricted
    (no "domains" list — those answer only their own names) and addressed
    by IP, plain or DoH (a hostname resolver would itself need a lookup
    before the tunnel exists). Otherwise DNS_BOOTSTRAP_FALLBACK."""
    for server in servers:
        if isinstance(server, dict):
            if server.get("domains"):
                continue
            address = server.get("address")
        else:
            address = server
        if not isinstance(address, str):
            continue
        host = urllib.parse.urlsplit(address).hostname if "://" in address else address
        if host and _is_ip(host):
            return address
    return DNS_BOOTSTRAP_FALLBACK


def _set_mark(outbound: dict) -> dict:
    sockopt = outbound.setdefault("streamSettings", {}).setdefault("sockopt", {})
    sockopt["mark"] = KILLSWITCH_MARK
    return outbound


# ── Server registry: subscription + captured union ────────────────────────────


def _configs() -> dict:
    try:
        data = json.loads(_happmeta().XRAY_CONFIGS.read_text())
    except OSError, json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def all_servers(allow_fetch: bool = True) -> list[dict]:
    """[{name, provider_id, provider_name, config(subscription raw)}] —
    everything we can connect to, grouped per provider.

    With allow_fetch=False the subscription caches are read as-is (fresh or
    stale) and the network is never touched — the bar widget's --status path.
    """
    servers = []
    for sub_id, prov in providers().items():
        url = prov.get("url")
        if not url:
            continue
        hm = _happmeta()
        cfgs = (
            hm.fetch_subscription(sub_id, url)
            if allow_fetch
            else hm.fetch_subscription_cached(sub_id)
        )
        for cfg in cfgs:
            if is_stub_server(cfg):  # caches written before stubs were filtered
                continue
            name = cfg.get("remarks") or "?"
            servers.append(
                {
                    "name": name,
                    "provider_id": sub_id,
                    "provider_name": prov["name"],
                    "config": cfg,
                }
            )
    # Captured servers missing from every subscription (e.g. old captures).
    # Matched by address (host, port), not name: a subscription can rename
    # or rotate a server onto a new address under the same display name,
    # which would otherwise leave the old capture looking like a distinct,
    # provider-less duplicate of a server that's actually still around
    # (see CLAUDE.md's "Other / no provider" notes) — a capture whose
    # own address can't be parsed falls back to the name-only check so it
    # is never wrongly hidden.
    known_names = {s["name"] for s in servers}
    known_targets = {
        target for s in servers if (target := _outbound_target(s["config"])) is not None
    }
    for name, cfg in _configs().items():
        if name in known_names:
            continue
        target = _outbound_target(cfg)
        if target is not None and target in known_targets:
            continue
        servers.append(
            {
                "name": name,
                "provider_id": "",
                "provider_name": "Other / no provider",
                "config": cfg,
            }
        )
    return servers


def match_server(name: str, servers: list[dict], provider_id: str | None = None) -> dict | None:
    """The server a name refers to: exact match, or the unique substring
    match (GUI names from Happ.conf can lack the emoji prefix). None when
    ambiguous or missing — a prefix must never select the wrong server.

    Names are only unique within one subscription, so a known provider_id
    narrows the search to that subscription first; when it has no such
    server (subscription removed or re-keyed since) the name alone decides,
    as before."""
    if provider_id:
        own = [s for s in servers if s["provider_id"] == provider_id]
        if own and (found := match_server(name, own)) is not None:
            return found
    exact = [s for s in servers if name == s["name"]]
    if exact:
        return exact[0]
    subs = [s for s in servers if name in s["name"] or s["name"] in name]
    return subs[0] if len(subs) == 1 else None


def resolve_config(
    name: str,
    allow_fetch: bool = True,
    provider_id: str | None = None,
    tunnel_dns: bool = True,
) -> dict | None:
    """Runnable xray config for a server name: merged from the subscription
    when available, otherwise a captured config used as-is."""
    servers = all_servers(allow_fetch=allow_fetch)
    server = match_server(name, servers, provider_id)
    if server is not None:
        if server["provider_id"]:
            return build_runtime_config(server["config"], tunnel_dns=tunnel_dns)
        return server["config"]  # captured fallback
    return _configs().get(name)


# ── Server params / labels ────────────────────────────────────────────────────


def _real_outbound(cfg: dict) -> dict | None:
    """The server outbound (vless preferred; trojan/shadowsocks fall back to
    the first non-dns/freedom outbound), or None."""
    outbounds = cfg.get("outbounds") or []
    return next((o for o in outbounds if o.get("protocol") == "vless"), None) or next(
        (o for o in outbounds if o.get("protocol") not in NON_PROXY_PROTOCOLS), None
    )


def _outbound_target(cfg: dict) -> tuple[str, int] | None:
    """(host, port) of a raw xray config's real server outbound, or None —
    the address identity that actually distinguishes one server from
    another, independent of its display name (see all_servers())."""
    outbound = _real_outbound(cfg)
    if outbound is None:
        return None
    try:
        settings = outbound.get("settings", {})
        if "vnext" in settings:  # vless / vmess
            target = settings["vnext"][0]
        elif "servers" in settings:  # trojan / shadowsocks
            target = settings["servers"][0]
        elif "address" in settings:  # hysteria and other flat-settings outbounds
            target = settings
        else:
            return None
        return (target["address"], target["port"])
    except KeyError, IndexError, TypeError:
        return None


def subscription_targets() -> list[tuple[str, str, int]]:
    """(provider name, host, port) of every subscription URL — the killswitch
    must let these through: the plugin fetches subscriptions through xray,
    and Happ's routing often sends a Russian-hosted subscription host
    `direct`, which the killswitch otherwise blocks (subscriptions then
    can't refresh, and a cleared cache leaves the Happ menu empty)."""
    targets = []
    for prov in providers().values():
        url = urllib.parse.urlsplit(prov.get("url") or "")
        if url.hostname:
            targets.append((prov["name"], url.hostname, url.port or 443))
    return targets


def server_endpoints_of(cfg: dict) -> list[tuple[str, int]]:
    """(host, port) of EVERY proxy outbound — a balancer config fans out
    over several servers and xray may dial any of them, so a killswitch
    whitelist built from _outbound_target()'s first match alone would cut
    the tunnel the moment the balancer picks another member."""
    endpoints = []
    for outbound in cfg.get("outbounds") or []:
        if outbound.get("protocol") in NON_PROXY_PROTOCOLS:
            continue
        target = _outbound_target({"outbounds": [outbound]})
        if target is not None and target not in endpoints:
            endpoints.append(target)
    return endpoints


def server_endpoints(
    name: str, allow_fetch: bool = True, provider_id: str | None = None
) -> list[tuple[str, int]]:
    cfg = resolve_config(name, allow_fetch=allow_fetch, provider_id=provider_id)
    return server_endpoints_of(cfg) if cfg else []


def server_params(
    name: str, allow_fetch: bool = True, provider_id: str | None = None
) -> dict | None:
    """{host, port, protocol, network, security} for a server."""
    cfg = resolve_config(name, allow_fetch=allow_fetch, provider_id=provider_id)
    if not cfg:
        return None
    outbound = _real_outbound(cfg)
    if outbound is None:
        return None
    target = _outbound_target(cfg)
    if target is None:
        return None
    stream = outbound.get("streamSettings", {})
    try:
        return {
            "host": target[0],
            "port": target[1],
            "protocol": outbound["protocol"],
            "network": stream.get("network", "tcp"),
            "security": stream.get("security", ""),
        }
    except KeyError, IndexError, TypeError:
        return None
