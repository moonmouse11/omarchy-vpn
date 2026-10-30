import ipaddress
import time
from pathlib import Path

PING_TIMEOUT = 3.0

ROUTE_TABLE = Path("/proc/net/route")
SYS_NET = Path("/sys/class/net")
ARPHRD_NONE = "65534"  # link type of tun/wireguard/amneziawg devices
_FAKE_DNS_NET = ipaddress.ip_network("198.18.0.0/15")


def _happmeta():
    import happmeta as hm  # noqa: PLC0415 — tests patch happmeta.ROUTE_TABLE / .socket

    return hm


def uplink_interface() -> str | None:
    """The physical NIC behind the default route, skipping tunnels.

    A VPN puts its own default route on top (Happ: `default dev happ-xray
    metric 1` over `default via … dev wlp5s0 metric 600`); xray's TUN then
    completes every TCP handshake locally, so an unbound connect measured
    0.2-3 ms to every server. None when there is no non-tunnel default route."""
    hm = _happmeta()
    try:
        lines = hm.ROUTE_TABLE.read_text().splitlines()[1:]
    except OSError:
        return None
    routes = []
    for line in lines:
        f = line.split()
        # Iface Destination Gateway Flags RefCnt Use Metric Mask …
        if len(f) < 8 or f[1] != "00000000" or f[7] != "00000000" or not int(f[3], 16) & 1:
            continue
        try:
            link_type = (hm.SYS_NET / f[0] / "type").read_text().strip()
        except OSError:
            continue
        if link_type != hm.ARPHRD_NONE:
            routes.append((int(f[6]), f[0]))
    return min(routes)[1] if routes else None


def measure_ping(host: str, port: int) -> float | None:
    """TCP connect RTT (best of 2) to the server itself, None on failure.

    The socket is bound to uplink_interface() (SO_BINDTODEVICE, unprivileged
    since Linux 5.7) — the way xray reaches its own servers — so a running
    tunnel doesn't answer for them. Used for WireGuard/OpenVPN only (Happ
    and Keys go through xray, see delayping); under the kill switch these
    direct connects are dropped, so the Ping button skips them then."""
    hm = _happmeta()
    sock_mod = hm.socket
    family, kind, proto, _, addr = sock_mod.getaddrinfo(host, port, type=sock_mod.SOCK_STREAM)[0]
    if family == sock_mod.AF_INET and ipaddress.ip_address(addr[0]) in _FAKE_DNS_NET:
        return None  # the tunnel's fake DNS answered: no real address to time
    iface = _happmeta().uplink_interface()
    best = None
    for _ in range(2):
        with sock_mod.socket(family, kind, proto) as sock:
            sock.settimeout(PING_TIMEOUT)
            if iface:
                sock.setsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_BINDTODEVICE, iface.encode())
            start = time.perf_counter()
            try:
                sock.connect(addr)
            except OSError:
                return None
            ms = (time.perf_counter() - start) * 1000
            best = ms if best is None else min(best, ms)
    return round(best, 1) if best is not None else None
