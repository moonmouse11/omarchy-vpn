"""Concurrent settings saves preserve changes outside the current edit."""

import copy
import fcntl
import multiprocessing
import stat

import pytest

import config
from settings_tui import SettingsState


@pytest.fixture
def saved_config(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    config.save_config(config.Config())
    return config.CONFIG_PATH


def test_settings_save_preserves_newer_killswitch(saved_config):
    state = SettingsState([], [])
    newer = config.load_config()
    newer.killswitch_mode = "all"
    config.save_config(newer)
    state.draft.panel_key_hints = False
    assert state.save()
    assert config.load_config().killswitch_mode == "all"
    assert state.draft == state.saved == config.load_config()


def test_patch_merges_nested_keys_and_deletions(saved_config):
    previous = config.load_config()
    previous.ip_sources = {"abuseipdb": {"api_key": "old", "enabled": True}}
    config.save_config(previous)
    updated = copy.deepcopy(previous)
    del updated.ip_sources["abuseipdb"]["api_key"]
    newer = copy.deepcopy(previous)
    newer.ip_sources["abuseipdb"]["enabled"] = False
    newer.ip_sources["ipqualityscore"] = {"api_key": "keep"}
    config.save_config(newer)
    merged = config.save_config_changes(previous, updated)
    assert merged.ip_sources == {
        "abuseipdb": {"enabled": False},
        "ipqualityscore": {"api_key": "keep"},
    }
    assert config.load_config() == merged
    assert stat.S_IMODE(saved_config.stat().st_mode) == 0o600


def test_patch_does_not_erase_new_keys_in_an_initially_empty_dict(saved_config):
    previous = config.load_config()
    updated = copy.deepcopy(previous)
    updated.providers["happ"] = False
    newer = config.load_config()
    newer.providers["wireguard"] = False
    config.save_config(newer)
    config.save_config_changes(previous, updated)
    assert config.load_config().providers == {"wireguard": False, "happ": False}


def test_unmodified_patch_preserves_newer_same_setting(saved_config):
    previous = config.load_config()
    newer = copy.deepcopy(previous)
    newer.killswitch_mode = "all"
    config.save_config(newer)
    assert config.save_config_changes(previous, previous).killswitch_mode == "all"


def _save_patch(path, previous, key, start, finished):
    config.CONFIG_PATH = path
    updated = copy.deepcopy(previous)
    updated.providers[key] = False
    start.wait(5)
    config.save_config_changes(previous, updated)
    finished.put(key)


def test_independent_processes_merge_their_changes(saved_config):
    # Only temp config writes: never provider probing or host state.
    ctx = multiprocessing.get_context("spawn")
    start = ctx.Barrier(3)
    finished = ctx.Queue()
    previous = config.load_config()
    children = [
        ctx.Process(target=_save_patch, args=(saved_config, previous, key, start, finished))
        for key in ("happ", "wireguard")
    ]
    try:
        for child in children:
            child.start()
        start.wait(5)
        assert {finished.get(timeout=5), finished.get(timeout=5)} == {"happ", "wireguard"}
        for child in children:
            child.join(5)
            assert child.exitcode == 0
        assert config.load_config().providers == {"happ": False, "wireguard": False}
    finally:
        for child in children:
            if child.is_alive():
                child.terminate()
            child.join()
        finished.close()


def test_full_save_uses_the_same_lock(saved_config, monkeypatch):
    real_write = config.fsutil.write_json_atomic

    def require_locked(path, data, **kwargs):
        # A separate open file description cannot acquire our held lock.
        with path.with_suffix(".lock").open("a") as probe, pytest.raises(BlockingIOError):
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        real_write(path, data, **kwargs)

    monkeypatch.setattr(config.fsutil, "write_json_atomic", require_locked)
    config.save_config(config.Config())
