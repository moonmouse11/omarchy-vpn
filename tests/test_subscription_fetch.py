"""External subscription input stays bounded and never destroys a valid cache."""

import importlib
import importlib.util
import io
import json
import math
from typing import ClassVar

import pytest

import fsutil
from subscription import fetch

URL = "https://example.invalid/subscription"
VALID = {"remarks": "server", "outbounds": [{"protocol": "vless"}]}


class Response(io.BytesIO):
    headers: ClassVar[dict[str, str]] = {}  # no Content-Length: the byte bound still applies


def _answer(monkeypatch, payload):
    monkeypatch.setattr(fetch, "_open_https", lambda *a, **kw: Response(payload))


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

    monkeypatch.setattr(fetch, "_open_https", lambda *a, **kw: Endless())
    with pytest.raises(ValueError):
        fetch.download_subscription(URL, {})
    assert calls == [101]  # oversized content is not retried


def test_cache_record_validation_is_strict_and_returns_a_copy():
    spec = importlib.util.find_spec("subscription.cache")
    assert spec is not None, "subscription.cache must provide normalize_record"
    cache = importlib.import_module("subscription.cache")
    valid = {"at": 1.5, "url": "https://example/sub", "servers": [VALID]}

    normalized = cache.normalize_record(valid)

    assert normalized == valid
    assert normalized is not valid
    for value in (
        None,
        [],
        {"servers": []},
        {"at": "1", "servers": []},
        {"at": True, "servers": []},
        {"at": math.nan, "servers": []},
        {"at": math.inf, "servers": []},
        {"at": 1, "url": 7, "servers": []},
        {"at": 1, "servers": "broken"},
        {"at": 1, "servers": [VALID, None]},
    ):
        assert cache.normalize_record(value) is None


def test_malformed_cache_timestamp_refreshes_instead_of_crashing(tmp_path, monkeypatch):
    path = tmp_path / "sub.json"
    fsutil.write_json_atomic(
        path,
        {"url": URL, "at": "bad", "servers": [{"remarks": "stale"}]},
    )
    _answer(monkeypatch, json.dumps([VALID]).encode())

    servers, error = fetch.fetch_subscription_to_cache(path, URL, {})

    assert servers == [VALID]
    assert error is None


def test_invalid_cache_servers_never_escape_as_a_string(tmp_path, monkeypatch):
    path = tmp_path / "sub.json"
    fsutil.write_json_atomic(path, {"url": URL, "at": 1, "servers": "broken"})
    monkeypatch.setattr(
        fetch,
        "_open_https",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("offline")),
    )

    servers, error = fetch.fetch_subscription_to_cache(path, URL, {}, force=True)

    assert servers == []
    assert error == "offline"


def test_initial_http_is_rejected_before_open(monkeypatch):
    opened = []
    monkeypatch.setattr(
        fetch.urllib.request,
        "urlopen",
        lambda *args, **kwargs: opened.append(args) or Response(json.dumps([VALID]).encode()),
    )

    with pytest.raises(ValueError, match="HTTPS required"):
        fetch.download_subscription("http://panel.example/sub/TOKEN", {"X-HWID": "machine-id"})

    assert opened == []


def test_https_required_preserves_last_good_cache(tmp_path, monkeypatch):
    path = tmp_path / "sub.json"
    fsutil.write_json_atomic(
        path,
        {"url": "http://panel.example/sub", "at": 0, "servers": [VALID]},
    )
    opened = []
    monkeypatch.setattr(
        fetch.urllib.request,
        "urlopen",
        lambda *args, **kwargs: opened.append(args) or Response(json.dumps([VALID]).encode()),
    )

    servers, error = fetch.fetch_subscription_to_cache(
        path,
        "http://panel.example/sub",
        {"X-HWID": "machine-id"},
        force=True,
    )

    assert servers == [VALID]
    assert error == "HTTPS required"
    assert opened == []


def test_https_redirect_handler_rejects_downgrade_before_request(monkeypatch):
    captured = []

    class Opener:
        def open(self, request, timeout):
            captured.append((request, timeout))
            return Response(json.dumps([VALID]).encode())

    monkeypatch.setattr(
        fetch.urllib.request,
        "build_opener",
        lambda handler: captured.append(handler) or Opener(),
    )
    request = fetch.urllib.request.Request(
        "https://panel.example/sub/TOKEN",
        headers={"X-HWID": "machine-id"},
    )

    response = fetch._open_https(request, 3)
    handler = captured[0]
    https_request = handler.redirect_request(
        request,
        None,
        302,
        "Found",
        {},
        "https://next.example/sub/TOKEN",
    )
    with pytest.raises(ValueError, match="HTTPS required"):
        handler.redirect_request(
            https_request,
            None,
            302,
            "Found",
            {},
            "http://attacker.example/sub/TOKEN",
        )

    assert response.read() == json.dumps([VALID]).encode()
    assert https_request.full_url == "https://next.example/sub/TOKEN"
    assert all(not getattr(item, "full_url", "").startswith("http://") for item in captured)


def test_https_redirect_handler_allows_https(monkeypatch):
    handlers = []

    class Opener:
        def open(self, request, timeout):
            return Response(json.dumps([VALID]).encode())

    monkeypatch.setattr(
        fetch.urllib.request,
        "build_opener",
        lambda handler: handlers.append(handler) or Opener(),
    )
    request = fetch.urllib.request.Request("https://panel.example/sub")

    fetch._open_https(request, 3)
    redirected = handlers[0].redirect_request(
        request,
        None,
        302,
        "Found",
        {},
        "https://next.example/sub",
    )

    assert redirected.full_url == "https://next.example/sub"


def test_production_limit_is_generous_but_finite():
    assert fetch.MAX_SUBSCRIPTION_BYTES == 16 * 1024 * 1024
