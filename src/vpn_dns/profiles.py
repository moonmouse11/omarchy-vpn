"""Strict numeric runtime profile edits; stdlib only, no DNS or user-controlled paths."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from itertools import pairwise

_WG_HEADER = re.compile(r"\s*\[([^]]+)\]\s*(?:#.*)?$")
_WG_HOST = re.compile(r"\s*Endpoint\s*=\s*(\[[^]]+\]|[^:\s]+)\s*:\s*[0-9]+", re.IGNORECASE)
_PUBLIC_KEY = re.compile(r"\s*PublicKey\s*=\s*([^#\s]+)", re.IGNORECASE)
_REMOTE = re.compile(
    r"""\s*(?:(?:--)?setenv\s+opt\s+)?(?:--)?remote\s+("[^"\n]*"|'[^'\n]*'|[^\s#;]+)"""
)
_RANDOM = re.compile(r"\s*(?:(?:--)?setenv\s+opt\s+)?(?:--)?remote-random-hostname\s*(?:[#;].*)?$")
_TAG = re.compile(r"\s*<(/?)([a-zA-Z0-9_-]+)>\s*(?:[#;].*)?$")


@dataclass(frozen=True)
class Endpoint:
    line: int
    start: int
    end: int
    host: str
    peer: str = ""


def _ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def hostname(host: str) -> str:
    value = host.removesuffix(".").encode("idna").decode("ascii").lower()
    if (
        not value
        or len(value) > 253
        or any(
            not 0 < len(label) <= 63 or re.fullmatch(r"[a-z0-9_-]+", label) is None
            for label in value.split(".")
        )
    ):
        raise ValueError("Invalid profile endpoint hostname")
    return value


def _wg_line(line: str) -> tuple[str, list[int]]:
    # wg's parser removes ASCII whitespace, including inside keys and values.
    positions = [i for i, char in enumerate(line.split("#", 1)[0]) if char not in " \t\r\n\v\f"]
    return "".join(line[i] for i in positions), positions


def _wg_endpoints(lines: list[str]) -> list[Endpoint]:
    compact = [_wg_line(line) for line in lines]
    headers = [
        (i, match[1].lower())
        for i, (line, _) in enumerate(compact)
        if (match := _WG_HEADER.fullmatch(line))
    ]
    headers.append((len(lines), ""))
    found: list[Endpoint] = []
    for (start, section), (end, _) in pairwise(headers):
        if section != "peer":
            continue
        peer = next(
            (m[1] for line, _ in compact[start + 1 : end] if (m := _PUBLIC_KEY.match(line))), ""
        )
        found.extend(
            Endpoint(
                i,
                compact[i][1][match.start(1)],
                compact[i][1][match.end(1) - 1] + 1,
                match[1],
                peer,
            )
            for i in range(start + 1, end)
            if (match := _WG_HOST.match(compact[i][0]))
        )
    return found


def _ovpn_endpoints(lines: list[str]) -> tuple[list[Endpoint], list[int]]:
    found = []
    random_lines = []
    inline = ""
    for i, line in enumerate(lines):
        tag = _TAG.fullmatch(line.strip())
        if inline:
            if tag and tag[1] == "/" and tag[2].lower() == inline:
                inline = ""
            continue
        tokens = line.split()
        if not tokens or tokens[0].startswith(("#", ";")):
            continue
        options = tokens[:1]
        if tokens[0].removeprefix("--") == "setenv":
            options = tokens[:3] if len(tokens) > 1 and tokens[1] == "opt" else tokens[:2]
        # Native quoting/escaping of option names must not hide a hostname from this parser.
        if any(char in token for token in options for char in "\"'\\"):
            raise ValueError("Unsupported OpenVPN directive syntax; use plain option names")
        if tag and not tag[1] and tag[2].lower() != "connection":
            inline = tag[2].lower()
        elif match := _REMOTE.match(line):
            found.append(Endpoint(i, match.start(1), match.end(1), match[1].strip("\"'")))
        elif _RANDOM.fullmatch(line.strip()):
            random_lines.append(i)
    if inline:
        raise ValueError("Unterminated inline OpenVPN data")
    return found, random_lines


def endpoints(kind: str, text: str) -> list[Endpoint]:
    if kind in ("wg", "awg"):
        return _wg_endpoints(text.splitlines(keepends=True))
    if kind == "ovpn":
        return _ovpn_endpoints(text.splitlines(keepends=True))[0]
    raise ValueError("Invalid profile kind")


def describe(kind: str, text: str) -> dict[str, object]:
    hosts: set[str] = set()
    ipv4: set[str] = set()
    for record in endpoints(kind, text):
        try:
            address = ipaddress.ip_address(record.host.strip("[]"))
        except ValueError:
            hosts.add(hostname(record.host))
        else:
            if address.version == 4:
                ipv4.add(str(address))
    return {
        "hosts": sorted(hosts),
        "ipv4": sorted(ipv4),
        "random_hostname": kind == "ovpn" and bool(_ovpn_endpoints(text.splitlines())[1]),
    }


def numeric_config(kind: str, text: str, mapping: dict[str, str]) -> str:
    records = endpoints(kind, text)
    if kind in ("wg", "awg") and any(not r.peer and not _ip(r.host) for r in records):
        raise ValueError("Hostname endpoints require a peer PublicKey for SaveConfig restoration")
    required = {hostname(record.host) for record in records if not _ip(record.host)}
    if not isinstance(mapping, dict) or any(
        not isinstance(k, str) or not isinstance(v, str) for k, v in mapping.items()
    ):
        raise ValueError("Invalid endpoint map")
    normalized = {hostname(k): str(ipaddress.IPv4Address(v)) for k, v in mapping.items()}
    if len(normalized) != len(mapping) or set(normalized) != required:
        raise ValueError("Endpoint map must match the selected profile's hostnames")
    lines = text.splitlines(keepends=True)
    for record in records:
        if not _ip(record.host):
            line = lines[record.line]
            lines[record.line] = (
                line[: record.start] + normalized[hostname(record.host)] + line[record.end :]
            )
    if kind == "ovpn":
        _, random_lines = _ovpn_endpoints(lines)
        for i in random_lines:
            # Bootstrap already applied the random prefix; never resolve numeric remotes again.
            lines[i] = ""
    return "".join(lines)


def restore_hostnames(saved: str, original: str) -> str:
    """Retain SaveConfig's other state/port edits, matching peers by PublicKey, not order."""
    originals = {
        record.peer: record.host
        for record in endpoints("wg", original)
        if record.peer and not _ip(record.host)
    }
    lines = saved.splitlines(keepends=True)
    for record in endpoints("wg", saved):
        if record.peer in originals:
            line = lines[record.line]
            lines[record.line] = line[: record.start] + originals[record.peer] + line[record.end :]
    return "".join(lines)
