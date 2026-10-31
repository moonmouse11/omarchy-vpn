"""Bar widget JSON (--status) and panel hero state."""

import fcntl
import json

import config
import delayping
import happmeta
import ipinfo
import ipv6guard
import killswitch
import providers.happd.happ as happ_provider
import reputation
from app.checks import _exit_fits, _name_flag_country, _read_dns_verdict
from app.helpers import spawn_manager
from app.registry import active_connections
from app.switch import (
    KILLSWITCH_PROVIDERS,
    _enforce_ipv6_guard,
    _lock_holder,
    _our_process,
    _vm,
)
from providers.base import VPNConnection


def _iface_rate(iface: str | None) -> str | None:
    import vpn_manager as vm  # noqa: PLC0415 — tests patch vpn_manager.iface_rate

    return vm.iface_rate(iface)


def _iface_traffic(iface: str | None) -> str | None:
    if not iface:
        return None
    import vpn_manager as vm  # noqa: PLC0415

    return vm.iface_traffic(iface)


def _sample_iface_traffic(iface: str) -> None:
    import vpn_manager as vm  # noqa: PLC0415

    vm.sample_iface_traffic(iface)


# ── Status ────────────────────────────────────────────────────────────────────


def get_status() -> dict:
    """Aggregate ALL active connections across providers.

    Waybar-style classes: "vpn-connected" + "vpn-<provider>" per active provider,
    "vpn-disconnected" when nothing is up. Tooltip lists every active
    connection with per-interface traffic stats.
    """
    cfg = config.load_config()
    # every provider, hidden ones too: ⚙ Settings hides a protocol from the
    # server list, but a tunnel it has up (autostart, NM) is still a tunnel
    active = active_connections()
    _enforce_ipv6_guard(active, cfg)

    if not active:
        return {
            "text": " VPN",
            "tooltip": "VPN: not connected",
            "class": "vpn-disconnected",
            "panel": panel_state(active, cfg),
        }

    # before the tooltip loop: it saves a fresh traffic sample, and a rate
    # read after that compares against itself (~0 s apart) — the panel's
    # speed came out empty
    panel = panel_state(active, cfg)
    extra = f" (+{len(active) - 1})" if len(active) > 1 else ""
    classes = ["vpn-connected"]
    tooltip = []
    for conn in active:
        classes.append(f"vpn-{conn.provider.lower()}")
        line = conn.label
        if conn.interface:
            # rate first (units per second, like the menu), then totals —
            # plain arrows on both rows confused "B/s" with "MiB"
            rate = _iface_rate(conn.interface)
            traffic = _iface_traffic(conn.interface)
            if rate:
                line += f"\n  {rate}"
            if traffic:
                line += f"\n  {traffic} total"
            _sample_iface_traffic(conn.interface)  # next tick can show a rate
        tooltip.append(line)

    if cfg.exit_ip_enabled:
        exit_line = ipinfo.status_line(active[0].name, cfg.exit_ip_max_age)
        if exit_line:
            tooltip.append(exit_line)
        else:
            request_ip_update(active[0].name)

    first = active[0]
    return {
        "text": f" {first.label}{extra}",
        "tooltip": "\n".join(tooltip),
        "class": classes,
        "panel": panel,
    }


def emit_status_json() -> None:
    """Print bar widget JSON to stdout — the only --status output path."""
    print(json.dumps(get_status()))


def _badge(badge_id: str, label: str, state: str, hint: str) -> dict:
    """One protection badge. state: "ok" | "bad" | "unknown"."""
    return {"id": badge_id, "label": label, "state": state, "hint": hint}


def _exit_badge(conn: VPNConnection, max_age: int) -> dict:
    """Does the exit IP sit where the server says it is? Cache-only (the
    tooltip path schedules the lookup); expected country as in the DNS
    leak test: the flag in the name, else the sweep's entry country."""
    cache = ipinfo.read_cache()
    if cache is None or not ipinfo.is_fresh(cache, conn.name, max_age):
        return _badge("exit", "Exit: checking", "unknown", "Looking up the public exit IP")
    country = (cache.get("country_code") or "").upper()
    flag = ipinfo.flag_emoji(country)
    ip = cache.get("ip") or "?"
    expected = _name_flag_country(conn.name) or reputation.country_of(conn.name)
    if not expected or not country:
        return _badge(
            "exit", f"Exit {flag}".strip(), "unknown", f"Exit IP {ip}; nothing to compare"
        )
    if _exit_fits(expected, country):
        return _badge("exit", f"Exit {flag}", "ok", f"Exit IP {ip} is where the server says")
    return _badge(
        "exit",
        f"Exit {flag} ≠ {ipinfo.flag_emoji(expected)}",
        "bad",
        f"Exit IP {ip} is not in the server's country — geo databases can disagree; "
        "run the DNS leak test for a second opinion",
    )


def _dns_badge(conn: VPNConnection) -> dict:
    record = _read_dns_verdict(conn.name)
    if record is None or record.get("leaked") is None:
        return _badge("dns", "DNS: untested", "unknown", "Run the DNS leak test for this server")
    if record["leaked"]:
        return _badge("dns", "DNS leaks", "bad", str(record.get("summary") or ""))
    return _badge("dns", "DNS private", "ok", str(record.get("summary") or ""))


PROTECTION_CHECKS = ("exit", "dns", "ipv6")


# The bar label's labelFormat placeholders (Widget.qml fills them).
LABEL_FIELDS = (
    "label", "provider", "subscription", "server", "count", "state",
    "exit_ip", "exit_country", "exit_flag",
    "rate", "down", "up", "total", "total_down", "total_up",
    "ping", "protocol", "interface", "sub_traffic", "sub_expire",
    "dns", "ipv6", "killswitch", "activity", "connecting",
)  # fmt: skip


def _split_arrows(text: str) -> tuple[str, str]:
    """ "↓ 3 KiB/s ↑ 4 KiB/s" -> ("3 KiB/s", "4 KiB/s"); ("", "") when absent."""
    down, _, up = text.partition("↑")
    return down.replace("↓", "").strip(), up.strip()


def _switch_in_progress() -> str | None:
    """Action line from whoever holds SWITCH_LOCK, or None when idle."""
    vm = _vm()
    lock = vm.SWITCH_LOCK
    vm_os = vm.os
    if not lock.is_file():
        return None
    try:
        fd = vm_os.open(lock, vm_os.O_RDONLY)
    except OSError:
        return None
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return None
        except BlockingIOError:
            lock_holder = getattr(vm, "_lock_holder", _lock_holder)
            our_process = getattr(vm, "_our_process", _our_process)
            pid, action = lock_holder(fd)
            if pid and not our_process(pid):
                return None
            return action or None
    finally:
        vm_os.close(fd)


def connecting_text() -> str:
    """Mid-connect indicator for the bar label ({connecting})."""
    action = _switch_in_progress()
    if action and action.startswith("connecting to "):
        return "connecting"
    return ""


def activity_text() -> str:
    """Ping progress for {activity}: "ping 23/150", else ""."""
    progress = delayping.read_progress()
    if progress is None:
        return ""
    return f"ping {progress.get('done', 0)}/{progress.get('total', 0)}"


def _label_fields_for_connection(
    fields: dict[str, str],
    conn: VPNConnection,
    *,
    by_id: dict[str, str],
    rate: str,
    total: str,
    cfg,
) -> None:
    fields.update(
        label=conn.label,
        provider=conn.provider,
        subscription=conn.subscription_name or "",
        server=conn.name,
        interface=conn.interface or "",
        dns=by_id.get("dns", ""),
        ipv6=by_id.get("ipv6", ""),
        rate=rate,
        total=total,
    )
    fields["down"], fields["up"] = _split_arrows(rate)
    fields["total_down"], fields["total_up"] = _split_arrows(total)
    cache = ipinfo.read_cache()
    if cache and ipinfo.is_fresh(cache, conn.name, cfg.exit_ip_max_age):
        country = (cache.get("country_code") or "").upper()
        fields.update(
            exit_ip=str(cache.get("ip") or ""),
            exit_country=country,
            exit_flag=ipinfo.flag_emoji(country),
        )
    ms = happmeta.ping_ms(happmeta.ping_key(conn.name, conn.subscription_id))
    if ms is not None:
        fields["ping"] = f"{round(ms)} ms"
    fields["protocol"] = conn.provider
    if conn.provider == "Happ":
        server_cfg = happmeta.resolve_config(
            conn.name, allow_fetch=False, provider_id=conn.subscription_id
        )
        if server_cfg:
            fields["protocol"] = happmeta.protocol_label(server_cfg) or conn.provider
    info = happmeta.subscription_info(conn.subscription_id) if conn.subscription_id else None
    if info:
        used = happmeta.fmt_traffic(info.get("download"))
        if used != "?":
            fields["sub_traffic"] = f"{used} / {happmeta.fmt_limit(info.get('total'))}"
        expire = happmeta.fmt_expire(info.get("expire"))
        if expire != "?":
            fields["sub_expire"] = expire


def label_fields(
    active: list[VPNConnection], title: str, badges: list[dict], *, rate: str, total: str, cfg
) -> dict[str, str]:
    """Every value a bar label template can show, as display strings — ""
    when unknown, so the template drops it with its separator. Cache reads
    only: the 3 s tick pays for these (the subscription parse is memoized)."""
    fields = dict.fromkeys(LABEL_FIELDS, "")
    fields["state"] = title
    by_id = {b["id"]: b["label"] for b in badges}
    fields["killswitch"] = by_id.get("killswitch", "")
    fields["activity"] = activity_text()
    fields["connecting"] = connecting_text()
    if not active:
        return fields
    first = active[0]
    fields["count"] = str(len(active))
    _label_fields_for_connection(fields, first, by_id=by_id, rate=rate, total=total, cfg=cfg)
    return fields


def _killswitch_unsupported(active: list[VPNConnection]) -> bool:
    """A NetworkManager connection is up: the kill switch has no rules for
    it (endpoints not parsed) and is suspended, so it isn't offered or shown."""
    return any(c.provider not in ("Happ", *KILLSWITCH_PROVIDERS) for c in active)


def _window_tools(active: list[VPNConnection], cfg) -> list[str]:
    """The app window's Tools buttons: what ⚙ Settings didn't hide (Settings
    itself can't be), the kill switch only where it works."""
    from app.tools import TOOLS  # noqa: PLC0415 — avoid import cycle with tools → status

    keys = [
        k
        for k, _label, _fn in TOOLS
        if k == "settings" or (k != "refresh_all" and cfg.tool_visible(k))
    ]
    if cfg.tool_visible("killswitch") and not _killswitch_unsupported(active):
        keys.append("killswitch")
    return keys


def _killswitch_badge(ks_on: bool) -> dict:
    if ks_on:
        return _badge("killswitch", "Kill switch on", "ok", "Traffic outside the tunnel is blocked")
    return _badge(
        "killswitch", "Kill switch off", "unknown", "Nothing stops a leak if the tunnel drops"
    )


def _ipv6_badge(ipv6_off: bool, cfg) -> dict:
    if ipv6_off:
        return _badge("ipv6", "IPv6 blocked", "ok", "IPv6 is off while the VPN is up")
    why = "" if cfg.ipv6_guard else " — IPv6 guard is off in ⚙ Settings"
    return _badge("ipv6", "IPv6 leaks", "bad", f"IPv6 is on and bypasses the tunnel{why}")


def _protection_title(badges: list[dict]) -> tuple[str, str]:
    checks = [b["state"] for b in badges if b["id"] in PROTECTION_CHECKS]
    if "bad" in checks:
        return "at_risk", "At risk"
    if all(c == "ok" for c in checks):
        return "protected", "Protected"
    return "unverified", "Unverified"


def _panel_state_disconnected(
    active: list[VPNConnection], cfg, ks_on: bool, ks_badge: dict
) -> dict:
    title = "Traffic blocked" if ks_on else "Not protected"
    meta = "Kill switch holds traffic until a VPN connects" if ks_on else "VPN is off"
    return {
        "connected": False,
        "state": "blocked" if ks_on else "off",
        "title": title,
        "meta": meta,
        "detail": "",
        "exit_ip": "",
        "rate": "",
        "total": "",
        "badges": [ks_badge],
        "key_hints": cfg.panel_key_hints,
        "tools": _window_tools(active, cfg),
        "fields": label_fields([], title, [ks_badge], rate="", total="", cfg=cfg),
    }


def _panel_state_connected(
    active: list[VPNConnection], cfg, ks_badge: dict, ipv6_off: bool
) -> dict:
    first = active[0]
    badges = [
        _exit_badge(first, cfg.exit_ip_max_age),
        _dns_badge(first),
        _ipv6_badge(ipv6_off, cfg),
    ]
    if not _killswitch_unsupported(active):
        badges.append(ks_badge)
    if first.provider == "Happ" and happ_provider.app_owns_connection():
        badges.append(
            _badge(
                "happ_app",
                "Happ app connection",
                "unknown",
                "Started in the Happ app, not by this plugin — use one or the other",
            )
        )
    meta = first.label.removeprefix(f"{first.provider} · ").removeprefix(f"{first.provider}: ")
    cache = ipinfo.read_cache()
    exit_ip = ""
    if cache and ipinfo.is_fresh(cache, first.name, cfg.exit_ip_max_age):
        exit_ip = f"{cache.get('ip')} {ipinfo.flag_emoji(cache.get('country_code'))}".strip()
    detail = first.provider + (f" +{len(active) - 1}" if len(active) > 1 else "")
    state, title = _protection_title(badges)
    rate = (_iface_rate(first.interface) or "") if first.interface else ""
    total = (_iface_traffic(first.interface) or "") if first.interface else ""
    return {
        "connected": True,
        "state": state,
        "title": title,
        "meta": meta,
        "detail": detail,
        "exit_ip": exit_ip,
        "rate": rate,
        "total": total,
        "badges": badges,
        "key_hints": cfg.panel_key_hints,
        "tools": _window_tools(active, cfg),
        "fields": label_fields(active, title, badges, rate=rate, total=total, cfg=cfg),
    }


def panel_state(active: list[VPNConnection], cfg) -> dict:
    """What the bar panel draws: a hero (state, connection, exit) and the
    protection badges. Built from caches and cheap probes only — it rides
    on the 3 s --status tick (the kill switch via its 30 s state cache)."""
    ks_on = killswitch.cached_is_enabled()
    ipv6_off = ipv6guard.is_disabled()
    ks_badge = _killswitch_badge(ks_on)
    if not active:
        return _panel_state_disconnected(active, cfg, ks_on, ks_badge)
    return _panel_state_connected(active, cfg, ks_badge, ipv6_off)


def request_ip_update(connection_name: str):
    """Fire-and-forget background exit-IP refresh (never blocks the bar)."""
    spawn_manager("--update-ip", connection_name)
