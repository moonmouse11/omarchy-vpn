"""Verified public entry-point labels, not egress ranges or a safety allowlist.

An authoritative server may observe different source IPs; unknown addresses retain
reported org/ASN metadata. Never infer an entire hosting ASN is a DNS service.
"""

# Official address documentation checked 2026-11-01; identity only, no marketing claims.
RESOLVER_NAMES = {
    # https://developers.cloudflare.com/1.1.1.1/ip-addresses/
    "1.1.1.1": "Cloudflare",
    "1.0.0.1": "Cloudflare",
    # https://developers.google.com/speed/public-dns/docs/using
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    # https://adguard-dns.io/en/public-dns.html
    "94.140.14.14": "AdGuard DNS",
    "94.140.15.15": "AdGuard DNS",
    # https://docs.quad9.net/services/
    "9.9.9.9": "Quad9",
    "149.112.112.112": "Quad9",
    # https://www.opendns.com/setupguide/
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS",
    # https://cleanbrowsing.org/filters/ (these are Security, not Family/SafeSearch)
    "185.228.168.9": "CleanBrowsing",
    "185.228.169.9": "CleanBrowsing",
    # https://docs.controld.com/docs/free-dns (unfiltered entry points)
    "76.76.2.0": "Control D",
    "76.76.10.0": "Control D",
    # https://dns.watch/
    "84.200.69.80": "DNS.WATCH",
    "84.200.70.40": "DNS.WATCH",
}


def resolver_name(address: str | None) -> str | None:
    return RESOLVER_NAMES.get(address or "")
