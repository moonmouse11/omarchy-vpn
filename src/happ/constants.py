"""Paths and xray constants shared across Happ modules."""

from pathlib import Path

LOG_FILE = Path.home() / ".local/share/Happ/logs/subscription_log.txt"
ROUTING_FILE = Path.home() / ".config/Happ/routing.json"
PROVIDERS_CACHE = Path.home() / ".cache/vpn-manager/happ-providers.json"
CAPTURED_PROVIDERS = Path.home() / ".config/happ-capture/xray-providers.json"
XRAY_CONFIGS = Path.home() / ".config/happ-capture/xray-configs.json"
HEADERS_FILE = Path.home() / ".config/happ-capture/headers.json"
SUB_CACHE_DIR = Path.home() / ".cache/vpn-manager"
# What a panel keys the full xray JSON on is a "Happ/<version>" User-Agent:
# without it (plain curl/urllib UA) a panel may answer a text/plain link list
# instead. Device-limited panels also want X-HWID, else they
# answer stub "servers" ("Client not supported"). Happ's HWID is the raw
# machine id (QSysInfo::machineUniqueId), so sending it makes us the same
# device as the GUI, not one more against the limit.
HAPP_GUI_BIN = "/usr/bin/happ"
HAPP_VERSION_FALLBACK = "4.5.2"
MACHINE_ID_FILES = (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id"))

SUB_MAX_AGE = 3600  # seconds
SUBS_REFRESH_RETRY = 60  # seconds, avoid spawning a worker per status tick when the tunnel is down
MANAGER = Path(__file__).resolve().parent.parent / "vpn_manager.py"

# Local inbounds the GUI adds to every subscription config (from a capture).
DEFAULT_INBOUNDS = [
    {
        "port": 10808,
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": True},
        "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True, "routeOnly": False},
        "tag": "socks",
    },
    {
        "port": 10809,
        "protocol": "http",
        "settings": {"allowTransparent": False},
        "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True, "routeOnly": False},
        "tag": "http",
    },
    {
        "protocol": "tun",
        "settings": {
            "autoOutboundsInterface": "auto",
            "autoSystemRoutingTable": ["0.0.0.0/0"],
            "gateway": ["172.19.0.1/30"],
            "mtu": 1500,
            "name": "happ-xray",
            "userLevel": 8,
        },
        "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True, "routeOnly": True},
        "tag": "tun-in",
    },
]

# SO_MARK put on xray's proxy outbounds (+ its own resolver, dns-direct);
# scripts/happ-killswitch accepts exactly this mark, so the killswitch lets
# the tunnel's own traffic out without guessing server IPs (balancers, UDP
# transports, domain addresses) — and when xray is down nothing carries it.
KILLSWITCH_MARK = 0x6B73  # "ks"
NON_PROXY_PROTOCOLS = ("freedom", "blackhole", "dns")

# xray's built-in resolver answers every app A/AAAA lookup (tun:53 ->
# dns-out -> handleIPQuery), tagged "dns-in". That tag deliberately has no
# rule of its own: lookups fall through to the same rules as app traffic
# (tunnel/balancer, or a subscription's split-tunnel "direct"). It used to
# go straight to dns-direct — every lookup left the real NIC from the real
# IP. Only the server's own hostnames may resolve outside the tunnel (the
# tunnel can't carry the lookup that finds it): a dedicated resolver entry,
# restricted to exactly those names and tagged DNS_BOOTSTRAP_TAG, goes to
# dns-direct — killswitch-marked, so blocking split-tunnel "direct" can't
# break the tunnel itself. (A DNS server's own "tag" is honoured by xray's
# routing on 26.3.27-26.9.30, verified against the real binaries.)
DNS_BOOTSTRAP_TAG = "dns-bootstrap"
DNS_BOOTSTRAP_FALLBACK = "https://1.1.1.1/dns-query"

LOCAL_ROUTING_RULES = [
    {"inboundTag": ["tun-in"], "outboundTag": "direct", "process": ["self/", "xray"]},
    {"inboundTag": [DNS_BOOTSTRAP_TAG], "outboundTag": "dns-direct"},
    {"inboundTag": ["tun-in"], "network": "tcp,udp", "outboundTag": "dns-out", "port": "53"},
]
CATCH_ALL_RULE = {"network": "tcp,udp", "outboundTag": "proxy"}
