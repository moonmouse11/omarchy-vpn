"""Bounded IPv4 DNS codec; no network, libc resolver or privileged code."""

import ipaddress
import re
import struct

MAX_REPLY = 65535
LABEL = re.compile(r"[a-z0-9_-]+", re.IGNORECASE)


class Truncated(ValueError):
    """The matching UDP response asks the caller to retry over TCP."""


def canonical(host: str) -> str:
    value = host.removesuffix(".").encode("idna").decode("ascii").lower()
    if (
        not value
        or len(value) > 253
        or any(
            not 0 < len(label) <= 63 or LABEL.fullmatch(label) is None for label in value.split(".")
        )
    ):
        raise ValueError("Invalid endpoint DNS name")
    return value


def query(host: str, identifier: int) -> bytes:
    labels = canonical(host).split(".")
    encoded = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\0"
    return struct.pack("!6H", identifier, 0x100, 1, 0, 0, 0) + encoded + struct.pack("!HH", 1, 1)


def _pointer(packet: bytes, offset: int, end: int | None) -> tuple[int, int]:
    if offset + 1 >= len(packet):
        raise ValueError("Truncated DNS pointer")
    target = ((packet[offset] & 0x3F) << 8) | packet[offset + 1]
    return target, offset + 2 if end is None else end


def _decoded(labels: list[str], end: int | None, offset: int) -> tuple[str, int]:
    value = ".".join(labels)
    if len(value) > 253:
        raise ValueError("Oversized DNS name")
    return value, end if end is not None else offset


def _name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    seen: set[int] = set()
    end = None
    while offset < len(packet) and len(seen) < 128:
        if offset in seen:
            raise ValueError("DNS compression cycle")
        seen.add(offset)
        size = packet[offset]
        if size & 0xC0 == 0xC0:
            offset, end = _pointer(packet, offset, end)
            continue
        if size & 0xC0:
            raise ValueError("Invalid DNS label")
        offset += 1
        if size == 0:
            return _decoded(labels, end, offset)
        label = packet[offset : offset + size].decode("ascii").lower()
        if len(label) != size or LABEL.fullmatch(label) is None:
            raise ValueError("Invalid DNS label")
        labels.append(label)
        offset += size
    raise ValueError("Invalid DNS name bounds")


def _address(packet: bytes, offset: int, end: int) -> str:
    if end - offset != 4:
        raise ValueError("Invalid DNS A length")
    return str(ipaddress.IPv4Address(packet[offset:end]))


def _records(packet: bytes, offset: int, count: int) -> tuple[dict[str, str], dict[str, str]]:
    addresses: dict[str, str] = {}
    aliases: dict[str, str] = {}
    for _ in range(count):
        owner, offset = _name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("Truncated DNS resource record")
        kind, family, _, size = struct.unpack_from("!HHIH", packet, offset)
        offset += 10
        end = offset + size
        if end > len(packet):
            raise ValueError("Truncated DNS resource data")
        if family == 1 and kind == 1:
            addresses.setdefault(owner, _address(packet, offset, end))
        elif family == 1 and kind == 5:
            target, consumed = _name(packet, offset)
            if consumed != end:
                raise ValueError("Invalid DNS CNAME length")
            aliases[owner] = target
        offset = end
    return addresses, aliases


def answer(packet: bytes, host: str, identifier: int) -> str | None:
    if not 12 <= len(packet) <= MAX_REPLY:
        raise ValueError("Invalid DNS response size")
    received_id, flags, questions, count, _, _ = struct.unpack_from("!6H", packet)
    if received_id != identifier or not flags & 0x8000 or flags & 0x7800 or questions != 1:
        raise ValueError("Unmatched DNS response header")
    expected = canonical(host)
    question, offset = _name(packet, 12)
    if question != expected or packet[offset : offset + 4] != struct.pack("!HH", 1, 1):
        raise ValueError("Unmatched DNS response question")
    if flags & 0x200:
        raise Truncated("DNS UDP response truncated")
    rcode = flags & 0xF
    if rcode == 3:  # NXDOMAIN is terminal; server failures may use another configured upstream.
        return None
    if rcode:
        raise ValueError(f"DNS server returned error {rcode}")
    if count > 256:
        raise ValueError("Too many endpoint DNS answers")
    addresses, aliases = _records(packet, offset + 4, count)
    for _ in range(len(aliases) + 1):
        if expected in addresses:
            return addresses[expected]
        if expected not in aliases:
            return None
        expected = aliases[expected]
    raise ValueError("DNS CNAME cycle")
