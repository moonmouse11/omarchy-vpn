import contextlib
import ipaddress
import re
import shutil
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


def _measure_tcp(host: str, port: int, iface: str | None) -> float | None:
    """TCP connect RTT (best of 2) to host:port."""
    hm = _happmeta()
    remote = getattr(hm, "_measure_tcp", None)
    if remote is not None and remote is not _measure_tcp:
        return remote(host, port, iface)
    sock_mod = hm.socket
    try:
        family, kind, proto, _, addr = sock_mod.getaddrinfo(host, port, type=sock_mod.SOCK_STREAM)[
            0
        ]
    except OSError, ValueError:
        return None
    if family == sock_mod.AF_INET and ipaddress.ip_address(addr[0]) in _FAKE_DNS_NET:
        return None  # the tunnel's fake DNS answered: no real address to time
    best = None
    for _ in range(2):
        with sock_mod.socket(family, kind, proto) as sock:
            sock.settimeout(PING_TIMEOUT)
            if iface:
                with contextlib.suppress(OSError):
                    sock.setsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_BINDTODEVICE, iface.encode())
            start = time.perf_counter()
            try:
                sock.connect(addr)
            except OSError:
                continue
            ms = (time.perf_counter() - start) * 1000
            best = ms if best is None else min(best, ms)
    return round(best, 1) if best is not None else None


def _parse_ping_rtt(output: str) -> float | None:
    """Milliseconds from iputils `ping` stdout (Linux)."""
    m = re.search(r"time[=<]([\d.]+)\s*ms", output)
    if not m:
        m = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", output)
    if not m:
        return None
    return round(float(m.group(1)), 1)


def _measure_icmp(host: str, iface: str | None) -> float | None:
    """ICMP echo RTT to host (WireGuard/AmneziaWG endpoints are UDP-only)."""
    hm = _happmeta()
    remote = getattr(hm, "_measure_icmp", None)
    if remote is not None and remote is not _measure_icmp:
        return remote(host, iface)
    subp = hm.subprocess
    if shutil.which("ping") is None:
        return None
    target = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    wait = max(1, int(PING_TIMEOUT))
    cmd = ["ping", "-n", "-c", "1", "-W", str(wait)]
    if iface:
        cmd.extend(["-I", iface])
    cmd.append(target)
    try:
        proc = subp.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=PING_TIMEOUT + wait + 1,
            check=False,
        )
    except OSError, subp.TimeoutExpired:
        return None
    if proc.returncode != 0:
        return None
    return _parse_ping_rtt(proc.stdout + proc.stderr)


def measure_ping(host: str, port: int, *, icmp_only: bool = False) -> float | None:
    """TCP connect RTT to host:port, else ICMP echo to the host.

    The socket is bound to uplink_interface() (SO_BINDTODEVICE, unprivileged
    since Linux 5.7) — the way xray reaches its own servers — so a running
    tunnel doesn't answer for them. Used for WireGuard/OpenVPN only (Happ
    and Keys go through xray, see delayping); under the kill switch these
    direct probes are dropped, so the Ping button skips them then. UDP-only
    WireGuard/AmneziaWG [Peer] endpoints never accept TCP — pass icmp_only
    to skip TCP and measure ICMP only."""
    hm = _happmeta()
    iface = hm.uplink_interface()
    if not icmp_only:
        ms = _measure_tcp(host, port, iface)
        if ms is not None:
            return ms
    return _measure_icmp(host, iface)
