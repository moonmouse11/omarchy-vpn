"""Real process schedules must not lose credentials across any store writer."""

import fcntl
import json
import multiprocessing
from pathlib import Path

import pytest

import providers.happd.keys as impl
import providers.keys as keys


def _key(name):
    return {
        "kind": "ss",
        "method": "aes-256-gcm",
        "password": "synthetic-test-only",
        "name": name,
        "host": name + ".invalid",
        "port": 443,
    }


def _operate(
    path, operation, name, started, done, results, loaded=None, release=None, display_name=None
):
    keys.STORE = Path(path)
    if loaded is not None:
        original = impl._load_servers

        def pause_after_real_read():
            snapshot = original()
            loaded.set()
            if not release.wait(10):
                raise TimeoutError("parent did not release paused store read")
            return snapshot

        impl._load_servers = pause_after_real_read
    started.set()
    if operation == "import":
        parsed = _key(name)
        if display_name is not None:
            parsed["name"] = display_name
        result = keys.add_server(parsed)
    elif operation == "delete":
        result = keys.KeysProvider("ss").delete_config(
            keys.VPNConnection(name="old", provider="Shadowsocks", active=False)
        )
    else:
        impl._ensure_uids()
        result = keys.ActionResult(True, "migrated")
    results.put((result.success, result.message))
    done.set()


def _cleanup(processes):
    for process in processes:
        process.join(10)
        if process.is_alive():
            process.terminate()
            process.join(5)


@pytest.mark.parametrize("first_operation", ["import", "delete", "migrate", "same-name"])
def test_overlapping_store_writers_preserve_unrelated_import(tmp_path, first_operation):
    path = tmp_path / "keys.json"
    path.write_text(json.dumps([_key("old")]))
    ctx = multiprocessing.get_context("spawn")
    loaded, release, started_a, started_b, done_a, done_b = [ctx.Event() for _ in range(6)]
    results = ctx.Queue()
    display_name = "shared" if first_operation == "same-name" else None
    operation = "import" if display_name else first_operation
    first = ctx.Process(
        target=_operate,
        args=(path, operation, "alpha", started_a, done_a, results, loaded, release, display_name),
    )
    second = ctx.Process(
        target=_operate,
        args=(path, "import", "beta", started_b, done_b, results, None, None, display_name),
    )
    processes = []
    try:
        first.start()
        processes.append(first)
        assert loaded.wait(5), "first writer never read its real store"
        second.start()
        processes.append(second)
        assert started_b.wait(5)
        # An unlocked second writer completes now, and its key is overwritten
        # by the paused first writer. A correct lock delays it until release.
        done_b.wait(0.5)
    finally:
        release.set()
        _cleanup(processes)
    assert all(p.exitcode == 0 for p in processes)
    assert all(results.get(timeout=2)[0] for _ in processes)
    saved = json.loads(path.read_text())
    expected = {"old", "alpha", "beta"} if first_operation == "import" else {"old", "beta"}
    if first_operation == "delete":
        expected = {"beta"}
    elif first_operation == "same-name":
        expected = {"old", "shared", "shared (2)"}
    assert {s["name"] for s in saved} == expected
    if first_operation == "migrate":
        assert all(s.get("uid") for s in saved)
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("operation", ["import", "delete", "migrate"])
def test_each_writer_waits_for_the_shared_store_lock(tmp_path, operation):
    path = tmp_path / "keys.json"
    path.write_text(json.dumps([_key("old")]))
    before = path.read_bytes()
    ctx = multiprocessing.get_context("spawn")
    started, done = ctx.Event(), ctx.Event()
    results = ctx.Queue()
    child = ctx.Process(target=_operate, args=(path, operation, "next", started, done, results))
    with path.with_suffix(".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        child.start()
        try:
            assert started.wait(5)
            assert not done.wait(0.3), "writer bypassed the shared lock"
            assert path.read_bytes() == before
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
            _cleanup([child])
    assert child.exitcode == 0
    assert results.get(timeout=2)[0]


def test_failed_save_preserves_credentials_and_releases_lock(tmp_path, monkeypatch):
    path = tmp_path / "keys.json"
    monkeypatch.setattr(keys, "STORE", path)
    assert keys.add_server(_key("old")).success
    before = path.read_bytes()
    original = impl.fsutil.write_json_atomic

    def fail(*args, **kwargs):
        raise OSError("synthetic disk failure")

    monkeypatch.setattr(impl.fsutil, "write_json_atomic", fail)
    with pytest.raises(OSError, match="synthetic disk failure"):
        keys.add_server(_key("failed"))
    assert path.read_bytes() == before
    monkeypatch.setattr(impl.fsutil, "write_json_atomic", original)
    ctx = multiprocessing.get_context("spawn")
    started, done = ctx.Event(), ctx.Event()
    results = ctx.Queue()
    child = ctx.Process(target=_operate, args=(path, "import", "next", started, done, results))
    child.start()
    try:
        assert done.wait(5), "failed writer retained the store lock"
    finally:
        _cleanup([child])
    assert child.exitcode == 0
    assert results.get(timeout=2)[0]
    assert {s["name"] for s in keys._load_servers()} == {"old", "next"}
