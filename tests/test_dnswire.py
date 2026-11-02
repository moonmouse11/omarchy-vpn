"""Bounded DNS parsing, independent of libc and privileged socket creation."""

import importlib
import importlib.util
import struct

import pytest

ID = 0x1234
HOST = "vpn.example"


def test_dns_wire_codec_is_available():
    assert importlib.util.find_spec("vpn_dns.wire") is not None


@pytest.fixture
def wire():
    assert importlib.util.find_spec("vpn_dns.wire") is not None, (
        "endpoint DNS wire codec is missing"
    )
    return importlib.import_module("vpn_dns.wire")


def name(value):
    return b"".join(bytes([len(label)]) + label.encode() for label in value.split(".")) + b"\0"


def packet(records, *, identifier=ID, flags=0x8180, question=HOST):
    return (
        struct.pack("!6H", identifier, flags, 1, len(records), 0, 0)
        + name(question)
        + struct.pack("!HH", 1, 1)
        + b"".join(records)
    )


def record(owner, kind, data):
    return owner + struct.pack("!HHIH", kind, 1, 30, len(data)) + data


def test_query_is_a_only_and_preserves_id(wire):
    assert wire.query("VPN.Example.", ID) == struct.pack("!6H", ID, 0x100, 1, 0, 0, 0) + name(
        HOST
    ) + struct.pack("!HH", 1, 1)


def test_compressed_answer_and_cname_chain(wire):
    a = record(b"\xc0\x0c", 1, b"\xc0\x00\x02\x01")
    assert wire.answer(packet([a]), HOST, ID) == "192.0.2.1"
    cname = record(b"\xc0\x0c", 5, name("real.example"))
    real = record(name("real.example"), 1, b"\xc0\x00\x02\x02")
    assert wire.answer(packet([real, cname]), HOST, ID) == "192.0.2.2"


def test_unrelated_records_do_not_supply_endpoint(wire):
    unrelated = record(name("other.example"), 1, b"\xc0\x00\x02\x01")
    assert wire.answer(packet([unrelated]), HOST, ID) is None


@pytest.mark.parametrize(
    "value", ["", "foo..example", "bad\n.example", "a" * 64 + ".example", "a." * 128]
)
def test_invalid_query_names_are_rejected(wire, value):
    with pytest.raises(ValueError):
        wire.query(value, ID)


@pytest.mark.parametrize(
    "kwargs", [{"identifier": ID + 1}, {"question": "other.example"}, {"flags": 0x0100}]
)
def test_response_transaction_and_question_must_match(wire, kwargs):
    with pytest.raises(ValueError):
        wire.answer(packet([], **kwargs), HOST, ID)


def test_truncation_is_explicit_for_tcp_retry_and_nxdomain_has_no_address(wire):
    with pytest.raises(wire.Truncated):
        wire.answer(packet([], flags=0x8380), HOST, ID)
    assert wire.answer(packet([], flags=0x8183), HOST, ID) is None


@pytest.mark.parametrize("owner", [b"\xff\xff", b"\xc0\x1d", b"\x40bad"])
def test_invalid_or_cyclic_compression_is_bounded(wire, owner):
    with pytest.raises(ValueError):
        wire.answer(packet([record(owner, 1, b"\xc0\x00\x02\x01")]), HOST, ID)


def test_truncated_rdata_is_rejected(wire):
    data = packet([record(b"\xc0\x0c", 1, b"\xc0\x00\x02\x01")])
    with pytest.raises(ValueError):
        wire.answer(data[:-1], HOST, ID)
