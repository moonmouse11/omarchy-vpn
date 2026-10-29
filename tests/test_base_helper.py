"""Interruptible run_helper() — switch preemption must drop a stuck sudo/helper."""

import signal

import providers.base as base


def test_terminate_registered_subprocesses_sends_killpg(monkeypatch):
    killpg: list[tuple[int, int]] = []

    class SlowProc:
        pid = 12345

        def poll(self):
            return None

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(base.os, "getpgid", lambda pid: 999)
    monkeypatch.setattr(base.os, "killpg", lambda pg, sig: killpg.append((pg, sig)))
    base._helper_slot[0] = SlowProc()

    base.terminate_registered_subprocesses()

    assert base._helper_slot[0] is None
    assert (999, signal.SIGTERM) in killpg


def test_terminate_registered_subprocesses_is_noop_when_idle():
    base._helper_slot[0] = None
    base.terminate_registered_subprocesses()
    assert base._helper_slot[0] is None
