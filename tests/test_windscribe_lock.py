import multiprocessing
import stat
import threading

import pytest

from providers.vendor import windscribe_lock


def _hold_lock(path, ready):
    windscribe_lock.LOCK_FILE = path
    with windscribe_lock.cli_lock(1):
        ready.put(True)
        threading.Event().wait(30)


@pytest.fixture(autouse=True)
def lock_file(tmp_path, monkeypatch):
    path = tmp_path / "windscribe-cli.lock"
    monkeypatch.setattr(windscribe_lock, "LOCK_FILE", path)
    return path


def test_cli_lock_is_exclusive_and_times_out(lock_file):
    entered = threading.Event()
    release = threading.Event()

    def hold():
        with windscribe_lock.cli_lock(1):
            entered.set()
            release.wait(2)

    holder = threading.Thread(target=hold)
    holder.start()
    assert entered.wait(1)
    try:
        with pytest.raises(windscribe_lock.CliBusyError), windscribe_lock.cli_lock(0.03):
            pass
    finally:
        release.set()
        holder.join(1)

    with windscribe_lock.cli_lock(0.1):
        assert stat.S_IMODE(lock_file.stat().st_mode) == 0o600


def test_cli_lock_releases_after_exception():
    with pytest.raises(RuntimeError, match="boom"), windscribe_lock.cli_lock(0.1):
        raise RuntimeError("boom")

    with windscribe_lock.cli_lock(0.1):
        pass


def test_cli_lock_releases_when_holder_process_is_terminated(lock_file):
    ctx = multiprocessing.get_context("spawn")
    ready = ctx.Queue()
    holder = ctx.Process(target=_hold_lock, args=(lock_file, ready))
    try:
        holder.start()
        assert ready.get(timeout=2) is True
        holder.terminate()
        holder.join(2)
        assert holder.exitcode is not None
        with windscribe_lock.cli_lock(0.2):
            pass
    finally:
        if holder.is_alive():
            holder.terminate()
        holder.join()
        ready.close()
