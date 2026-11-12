"""External subscription input stays bounded and never destroys a valid cache."""

import io
import json
from typing import ClassVar

import pytest

import fsutil
from subscription import fetch

URL = "https://example.invalid/subscription"
VALID = {"remarks": "server", "outbounds": [{"protocol": "vless"}]}


class Response(io.BytesIO):
    headers: ClassVar[dict[str, str]] = {}  # no Content-Length: the byte bound still applies


def _answer(monkeypatch, payload):
    monkeypatch.setattr(fetch.urllib.request, "urlopen", lambda *a, **kw: Response(payload))


@pytest.mark.parametrize("body", [[VALID, None], [VALID, "broken"], [VALID, 7], {}, None])
def test_invalid_response_preserves_cache(tmp_path, monkeypatch, body):
    path = tmp_path / "sub.json"
    fsutil.write_json_atomic(path, {"url": URL, "at": 0, "servers": [VALID]})
    old_bytes = path.read_bytes()
    _answer(monkeypatch, json.dumps(body).encode())
    servers, error = fetch.fetch_subscription_to_cache(path, URL, {}, force=True)
    assert servers == [VALID]
    assert error == "not a subscription answer"
    assert path.read_bytes() == old_bytes


def test_oversized_response_preserves_cache(tmp_path, monkeypatch):
    path = tmp_path / "sub.json"
    fsutil.write_json_atomic(path, {"url": URL, "at": 0, "servers": [VALID]})
    old_bytes = path.read_bytes()
    monkeypatch.setattr(fetch, "MAX_SUBSCRIPTION_BYTES", 100)
    _answer(monkeypatch, b" " * 101)
    servers, error = fetch.fetch_subscription_to_cache(path, URL, {}, force=True)
    assert servers == [VALID]
    assert error is not None
    assert path.read_bytes() == old_bytes


def test_exact_byte_limit_is_accepted(monkeypatch):
    payload = json.dumps([VALID]).encode()
    monkeypatch.setattr(fetch, "MAX_SUBSCRIPTION_BYTES", len(payload))
    _answer(monkeypatch, payload)
    assert fetch.download_subscription(URL, {}) == ([VALID], None)


def test_read_is_bounded_before_decoding(monkeypatch):
    calls = []
    monkeypatch.setattr(fetch, "MAX_SUBSCRIPTION_BYTES", 100)

    class Endless(Response):
        def read(self, size=-1):
            assert size == 101  # a bounded read, not read-all or Content-Length trust
            calls.append(size)
            return b"x" * size

    monkeypatch.setattr(fetch.urllib.request, "urlopen", lambda *a, **kw: Endless())
    with pytest.raises(ValueError):
        fetch.download_subscription(URL, {})
    assert calls == [101]  # oversized content is not retried


def test_production_limit_is_generous_but_finite():
    assert fetch.MAX_SUBSCRIPTION_BYTES == 16 * 1024 * 1024
