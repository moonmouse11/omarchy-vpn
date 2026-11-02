"""One selected profile's answers feed both numeric endpoints and the firewall."""

import ipaddress
import json
import secrets

from providers.common import helper
from vpn_dns import bootstrap, profiles


def resolve_profile(kind: str, name: str) -> tuple[dict[str, str], list[str]]:
    code, output = helper.run_helper("profile-info", kind, name)
    if code:
        raise OSError(f"Cannot read profile endpoints: {output}")
    data = json.loads(output)
    if (
        not isinstance(data, dict)
        or set(data) != {"hosts", "ipv4", "random_hostname"}
        or not isinstance(data["hosts"], list)
        or not isinstance(data["ipv4"], list)
        or not isinstance(data["random_hostname"], bool)
        or any(not isinstance(host, str) for host in data["hosts"])
        or any(not isinstance(ip, str) for ip in data["ipv4"])
    ):
        raise ValueError("Invalid profile endpoint metadata")
    hosts = list(dict.fromkeys(profiles.hostname(host) for host in data["hosts"]))
    ips = {str(ipaddress.IPv4Address(ip)) for ip in data["ipv4"]}
    queries = {
        host: f"{secrets.token_hex(6)}.{host}" if data["random_hostname"] else host
        for host in hosts
    }
    answers = bootstrap.resolve(list(queries.values())) if queries else {}
    mapping = {}
    for host, query in queries.items():
        if query not in answers:
            raise OSError(f"Endpoint DNS returned no IPv4 address for {host}")
        mapping[host] = str(ipaddress.IPv4Address(answers[query]))
    ips.update(mapping.values())
    return mapping, sorted(ips)
