"""Server list JSON and panel connect/disconnect."""

from typing import NamedTuple

import config
import delayping
import happmeta
import logutil
import quickconnect
from app.checks import _name_flag_country
from app.helpers import notify, refresh_bar
from app.ping import _ping_worker_alive
from app.provider_lookup import provider_named as _provider_named
from app.registry import visible_providers
from app.switch import guarded_connect, guarded_disconnect
from providers.base import ActionResult, VPNConnection


def _guarded_connect(provider, connection: VPNConnection) -> ActionResult:
    import vpn_manager as vm  # noqa: PLC0415 — tests patch vpn_manager.guarded_connect

    remote = getattr(vm, "guarded_connect", None)
    if remote is not None and remote is not guarded_connect:
        return remote(provider, connection)
    return guarded_connect(provider, connection)


def _guarded_disconnect(provider, connection: VPNConnection) -> ActionResult:
    import vpn_manager as vm  # noqa: PLC0415 — tests patch vpn_manager.guarded_disconnect

    remote = getattr(vm, "guarded_disconnect", None)
    if remote is not None and remote is not guarded_disconnect:
        return remote(provider, connection)
    return guarded_disconnect(provider, connection)


# Duplicated from app.tools — keeps server_list() free of tools ↔ servers import cycle.
_IMPORT_KINDS = {
    "WireGuard": "file",
    "AmneziaWG": "file",
    "OpenVPN": "file",
    "NetworkManager": "file",
    "VLESS": "key",
    "Shadowsocks": "key",
}
_MANAGED_PROVIDERS = (
    "WireGuard",
    "AmneziaWG",
    "NetworkManager",
    "OpenVPN",
    "VLESS",
    "Shadowsocks",
)
_AUTOSTART_PROVIDERS = ("WireGuard", "AmneziaWG", "NetworkManager", "OpenVPN")

# ── Happ: providers -> servers (with ping/protocol info) ─────────────────────


def happ_server_groups(provider) -> tuple[list[dict], dict[str, list[dict]]]:
    """(all servers, subscription name -> its rows) with the active server
    marked — shared by the Happ menu and the panel's server list."""
    servers = happmeta.all_servers(allow_fetch=False)
    active_conns = [c for c in provider.connections() if c.active]

    # Exact match, or the unique substring match (GUI names can lack the
    # emoji prefix); ambiguous prefixes mark nothing. Matched by
    # (subscription, name) — the same name in another subscription is a
    # different server and must not light up too.
    matched = {
        (m["provider_id"], m["name"])
        for c in active_conns
        if (m := happmeta.match_server(c.name, servers, c.subscription_id))
    }
    groups: dict[str, list] = {}
    for server in servers:
        is_active = (server["provider_id"], server["name"]) in matched
        groups.setdefault(server["provider_name"], []).append(
            {
                "name": server["name"],
                "active": is_active,
                "provider_id": server["provider_id"],
                "protocol": happmeta.protocol_label(server["config"]),
            }
        )
    return servers, groups


# ── Panel: server list + connect/disconnect ───────────────────────────────────


def _server_row(entry: dict) -> dict:
    """One server for the panel. A stale ping (older than PING_MAX_AGE —
    pings are measured only on the Ping button) keeps its value with a "~"
    and stale=True — the panel dims it. "—": not measured last time
    (WireGuard/OpenVPN under the kill switch)."""
    key = happmeta.ping_key(entry["name"], entry.get("provider_id"))
    state, ms = happmeta.ping_status(key)
    if state == "none":
        ping = ""  # never measured: say nothing rather than guess
    elif state == "skipped":
        ping = "—"
    elif ms is None:
        ping = "timeout"
    else:
        ping = f"{ms:.0f} ms"
    if ms is not None and state == "stale":
        ping = "~" + ping  # an old number; an old timeout is just dimmed
    row = {
        "name": entry["name"],
        "active": bool(entry["active"]),
        "protocol": entry.get("protocol", ""),
        "ping": ping,
        "ping_ms": ms if state not in ("none", "skipped") else None,
        "stale": state == "stale",
        "ping_at": happmeta.ping_at(key),
        # the flag's country code, so the filter finds "Польша" by "pl"
        "country": (_name_flag_country(entry["name"]) or "").lower(),
    }
    if entry.get("orphan"):
        row["orphan"] = True
    return row


class PingState(NamedTuple):
    """What is being measured, for the panel's "…": every server (Ping-all),
    the queued scopes, and the run in progress — its scope (the queue's
    first; None for Ping-all) and start. A row of the running scope measured
    since that start shows its result while the rest are still measured."""

    every: bool = False
    queued: tuple = ()
    current: dict | None = None
    started: float = float("inf")


NOTHING_PINGING = PingState()


def _pinging() -> PingState:
    """A queue nobody works on (its worker died) is stale: shown as nothing."""
    progress = delayping.read_progress() or {}
    started = float(progress.get("started") or float("inf"))
    if progress.get("kind") == delayping.ALL:
        return PingState(every=True, started=started)
    queue = delayping.read_queue()
    if not queue or not _ping_worker_alive():
        return PingState()
    running = progress.get("kind") == delayping.QUEUED
    return PingState(
        queued=tuple(queue),
        current=queue[0] if running else None,
        started=started if running else float("inf"),
    )


def _server_group(
    group_id: str,
    provider: str,
    title: str,
    entries: list[dict],
    sub_id=None,
    *,
    pinging: PingState = NOTHING_PINGING,
):
    group_scope = {"group": group_id}
    group_pinging = pinging.every or group_scope in pinging.queued
    rows = [_server_row(e) for e in entries]
    for row, entry in zip(rows, entries, strict=True):
        server_scope = {"server": [provider, entry["name"], entry.get("provider_id") or ""]}
        scopes = [group_scope, server_scope]
        queued = group_pinging or server_scope in pinging.queued
        in_current_run = pinging.every or pinging.current in scopes
        # measured during the run in progress: its result shows already
        row["pinging"] = queued and not (in_current_run and row["ping_at"] >= pinging.started)
    reachable = [r["ping_ms"] for r in rows if r["ping_ms"] is not None]
    summary = ""
    if reachable:
        median = sorted(reachable)[len(reachable) // 2]
        stale = "~" if any(r["stale"] for r in rows if r["ping_ms"] is not None) else ""
        summary = f"✓ {len(reachable)}/{len(rows)} · {stale}{median:.0f} ms"
    return {
        "id": group_id,
        "provider": provider,
        "title": title,
        "subscription_id": sub_id or "",
        "summary": summary,
        "active": any(r["active"] for r in rows),
        "pinging": group_pinging,
        "servers": rows,
    }


HAPP_NO_HEADERS_TITLE = "⚠ No servers: the provider sent none (README: Happ setup)"


def server_list() -> dict:
    """--servers: the panel's list — every visible provider's connections,
    Happ split per subscription — with ping and protocol. Cache reads only
    (it runs when the panel opens); stale subscriptions refresh in the
    background like the menu's, pings only on the Ping button."""
    happmeta.request_subscription_update()
    pinging = _pinging()
    groups: list[dict] = []
    # every visible protocol, empty ones too: the window's tree/tabs/sidebar list them
    providers: list[dict] = []
    for provider in visible_providers():
        first = len(groups)
        providers.append(
            {
                "name": provider.name,
                "importer": _IMPORT_KINDS.get(provider.name),
                "manage": provider.name in _MANAGED_PROVIDERS,
                "autostart": provider.name in _AUTOSTART_PROVIDERS,
            }
        )
        if provider.name == "Happ":
            import vpn_manager as vm  # noqa: PLC0415 — tests patch vpn_manager.happ_server_groups

            groups_fn = getattr(vm, "happ_server_groups", happ_server_groups)
            if groups_fn is happ_server_groups:
                _servers, happ_groups = happ_server_groups(provider)
            else:
                _servers, happ_groups = groups_fn(provider)
            for pname, entries in happ_groups.items():
                sub_id = entries[0].get("provider_id") or ""
                groups.append(
                    _server_group(
                        f"happ:{sub_id}:{pname}", "Happ", pname, entries, sub_id, pinging=pinging
                    )
                )
            # a panel that answered stub rows instead of servers (device limit,
            # unsupported client) says why in its own words, not missing silently
            for sub_id, prov in happmeta.providers().items():
                if prov["name"] in happ_groups or not (
                    reasons := happmeta.subscription_rejection(sub_id)
                ):
                    continue
                title = f"{prov['name']} · ⚠ {reasons[0].removeprefix('⚠️').strip()}"
                groups.append(
                    _server_group(f"happ:{sub_id}:{prov['name']}", "Happ", title, [], sub_id)
                )
            # nothing at all with default headers: a panel may want Happ's own
            if len(groups) == first and not happmeta.has_headers():
                groups.append(_server_group("happ:no-headers", "Happ", HAPP_NO_HEADERS_TITLE, []))
        elif provider.name == "INCY":
            from providers.incy import incy_server_groups

            _servers, incy_groups = incy_server_groups(provider)
            for pname, entries in incy_groups.items():
                sub_id = entries[0].get("provider_id") or "" if entries else ""
                groups.append(
                    _server_group(
                        f"incy:{sub_id}:{pname}", "INCY", pname, entries, sub_id, pinging=pinging
                    )
                )
        else:
            try:
                conns = provider.connections()
            except Exception as e:  # noqa: BLE001 — one broken provider must not empty the list
                logutil.log(f"server list: {provider.name} skipped: {e!r}")
                conns = []
            if conns:
                entries = [
                    {
                        "name": c.name,
                        "active": c.active,
                        "orphan": (
                            c.active
                            and not c.config_path
                            and c.provider in ("WireGuard", "AmneziaWG")
                        ),
                    }
                    for c in conns
                ]
                groups.append(
                    _server_group(
                        provider.name, provider.name, provider.name, entries, pinging=pinging
                    )
                )
        mine = groups[first:]
        providers[-1]["total"] = sum(len(g["servers"]) for g in mine)
        providers[-1]["active"] = any(g["active"] for g in mine)
    return {
        "groups": groups,
        "providers": providers,
        "layout": config.load_config().locations_layout,
        "quick": _quick_connect(groups),
    }


def _quick_connect(groups: list[dict]) -> dict:
    """QUICK CONNECT: favourites and recent servers that are still in the list
    (with their ping and state), marking each starred row `favourite`; recent
    leaves out the favourites, `last` (the power switch) doesn't."""
    quick = quickconnect.load()
    starred = {(e["provider"], e["name"], e["sub_id"]) for e in quick["favourites"]}
    index: dict[tuple, tuple[dict, dict]] = {}
    for g in groups:
        for row in g["servers"]:
            key = (g["provider"], row["name"], g["subscription_id"])
            row["favourite"] = key in starred
            index.setdefault(key, (g, row))

    def chips(entries: list[dict]) -> list[dict]:
        out = []
        for e in entries:
            hit = index.get((e["provider"], e["name"], e["sub_id"]))
            if hit:
                g, row = hit
                out.append(
                    {
                        "provider": g["provider"],
                        "name": row["name"],
                        "sub_id": e["sub_id"],
                        "group": g["title"],
                        "active": row["active"],
                        "ping": row["ping"],
                    }
                )
        return out

    recent = chips(quick["recent"])
    return {
        "favourites": chips(quick["favourites"]),
        "recent": [c for c in recent if (c["provider"], c["name"], c["sub_id"]) not in starred],
        "last": recent[0] if recent else None,
    }


def panel_connect(provider_name: str, name: str, sub_id: str | None = None) -> ActionResult:
    """--connect from the panel: the same guarded_connect() as the menu
    (killswitch, IPv6 guard, one tunnel at a time, DNS autotest)."""
    provider = _provider_named(provider_name)
    if provider is None:
        return ActionResult(False, f"Unknown provider: {provider_name}")
    if provider.name == "Happ":
        sub_name = happmeta.providers().get(sub_id or "", {}).get("name") if sub_id else None
        conn = VPNConnection(
            name=name,
            provider="Happ",
            active=False,
            subscription_id=sub_id or None,
            subscription_name=sub_name,
        )
    else:
        found = next((c for c in provider.connections() if c.name == name), None)
        if found is None:
            return ActionResult(False, f"{provider_name}: {name} not found")
        conn = found
    result = _guarded_connect(provider, conn)
    if result.success:  # QUICK CONNECT's recent, and the power switch's "last server"
        quickconnect.remember(provider.name, name, sub_id if provider.name == "Happ" else None)
    return result


def panel_disconnect(provider_name: str, name: str) -> ActionResult:
    """--disconnect from the panel. Happ's active connection name can differ
    from the subscription's server name (GUI names lack the emoji), so for
    Happ any active connection of it is the one."""
    provider = _provider_named(provider_name)
    if provider is None:
        return ActionResult(False, f"Unknown provider: {provider_name}")
    active = [c for c in provider.connections() if c.active]
    conn = next((c for c in active if c.name == name), None)
    if conn is None and provider.name == "Happ" and active:
        conn = active[0]
    if conn is None:
        return ActionResult(False, f"{provider_name}: {name} is not connected")
    return _guarded_disconnect(provider, conn)


def _report(result: ActionResult) -> None:
    import vpn_manager as vm  # noqa: PLC0415 — tests patch vpn_manager._report

    remote = getattr(vm, "_report", None)
    if remote is not None and remote is not _report:
        remote(result)
        return
    if result.message:
        if result.success:
            notify("VPN", result.message)
        else:
            notify("VPN — Error", result.message, urgent=True)
    refresh_bar()


def _traffic_summary(info: dict | None) -> str | None:
    """'6.5 GB / ∞ · until 20.10.2026' from the panel's userinfo headers."""
    if not info:
        return None
    parts = []
    traffic = happmeta.fmt_traffic(info.get("download"))
    limit = happmeta.fmt_limit(info.get("total"))
    if traffic != "?" or limit != "∞":
        parts.append(f"{traffic} / {limit}")
    expire = happmeta.fmt_expire(info.get("expire"))
    if expire != "?":
        parts.append(f"until {expire}")
    return " · ".join(parts) or None


def subscription_report(failed: dict[str, str]) -> tuple[str, str]:
    """(title, body) after a manual refresh: per Happ provider its ping
    summary (cached sweep, like the menu row) and the panel's traffic;
    a provider that didn't update gets ⚠️ and why — its old list stays."""
    names_by_sub: dict[str, list[str]] = {}
    for server in happmeta.all_servers(allow_fetch=False):
        names_by_sub.setdefault(server["provider_id"], []).append(
            happmeta.ping_key(server["name"], server["provider_id"])
        )
    lines = []
    for sub_id, prov in happmeta.providers().items():
        if not prov.get("url"):
            continue
        name = prov["name"]
        names = names_by_sub.get(sub_id, [])
        count = f"{len(names)} server" + ("" if len(names) == 1 else "s")
        details = [
            happmeta.provider_ping_summary(names) or f"{count}, no ping yet",
            _traffic_summary(happmeta.subscription_info(sub_id)),
        ]
        line = f"{name}: " + " · ".join(d for d in details if d)
        if name in failed:
            line = f"⚠️ {line}\n    not updated: {failed[name]}"
        lines.append(line)
    title = (
        f"Happ — {len(failed)} subscription(s) not updated"
        if failed
        else "Happ — subscriptions updated"
    )
    return title, "\n".join(lines) or "No Happ subscriptions"
