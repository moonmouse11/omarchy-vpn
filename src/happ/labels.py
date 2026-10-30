"""Display helpers for server rows."""

from happ.servers import _real_outbound
from ping.cache import ping_mark


def protocol_label(cfg: dict) -> str:
    """'vless/tcp/reality', 'hysteria/tls', 'trojan/ws/tls' — the server
    outbound's protocol/transport/security, '' when there is none. A
    transport that just repeats the protocol name (hysteria) is dropped."""
    outbound = _real_outbound(cfg)
    if outbound is None or not outbound.get("protocol"):
        return ""
    stream = outbound.get("streamSettings") or {}
    protocol = outbound["protocol"]
    network = stream.get("network", "tcp")
    parts = [protocol, "" if network == protocol else network, stream.get("security", "")]
    return "/".join(p for p in parts if p)


def server_info_suffix(name: str, protocol: str = "") -> str:
    """'✓ 42 ms · vless/tcp/reality' for menu labels — ping_mark plus the
    protocol (precomputed by the caller via protocol_label() from configs it
    already holds: resolving per server here would re-read every
    subscription cache per row and could fetch a stale one synchronously)."""
    return " · ".join(p for p in (ping_mark(name), protocol) if p)
