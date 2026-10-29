"""Interruptible run_helper() — switch preemption must drop a stuck sudo/helper."""

import io
import signal
import subprocess

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


def test_terminate_registered_subprocesses_escalates_to_sigkill(monkeypatch):
    killpg: list[int] = []

    class StuckProc:
        pid = 55

        def poll(self):
            return None

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired("cmd", timeout)

    monkeypatch.setattr(base.os, "getpgid", lambda pid: 777)
    monkeypatch.setattr(base.os, "killpg", lambda pg, sig: killpg.append(sig))
    base._helper_slot[0] = StuckProc()

    base.terminate_registered_subprocesses()

    assert killpg == [signal.SIGTERM, signal.SIGKILL]


def test_terminate_registered_subprocesses_is_noop_when_idle():
    base._helper_slot[0] = None
    base.terminate_registered_subprocesses()
    assert base._helper_slot[0] is None


def test_run_helper_collects_stdout(monkeypatch):
    class DoneProc:
        pid = 42
        returncode = 0
        stdin = None

        def __init__(self):
            self.stdout = io.StringIO("helper ok")
            self._polls = [None, 0]

        def poll(self):
            return self._polls.pop(0)

    monkeypatch.setattr(base.subprocess, "Popen", lambda *a, **k: DoneProc())
    code, out = base.run_helper("endpoints", "wg", "home")
    assert code == 0
    assert out == "helper ok"
    assert base._helper_slot[0] is None


def test_run_helper_writes_stdin(monkeypatch):
    written: list[str] = []

    class InPipe:
        def write(self, data: str) -> None:
            written.append(data)

        def close(self) -> None:
            pass

    class DoneProc:
        pid = 43
        returncode = 0
        stdin = InPipe()

        def __init__(self):
            self.stdout = io.StringIO("")

        def poll(self):
            return 0

    monkeypatch.setattr(base.subprocess, "Popen", lambda *a, **k: DoneProc())
    code, _ = base.run_helper("import", "wg", "home", stdin="[Interface]\nx\n")
    assert code == 0
    assert written == ["[Interface]\nx\n"]


def test_run_helper_times_out(monkeypatch):
    class NeverProc:
        pid = 44
        returncode = None
        stdout = None
        stdin = None

        def poll(self):
            return None

        def wait(self, timeout=None):
            return 0

    times = iter([0.0, 61.0])
    monkeypatch.setattr(base.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(base.subprocess, "Popen", lambda *a, **k: NeverProc())
    monkeypatch.setattr(base.os, "getpgid", lambda pid: 1)
    monkeypatch.setattr(base.os, "killpg", lambda pg, sig: None)
    code, out = base.run_helper("up", "wg", "home", timeout=60)
    assert code == 1
    assert out == "timeout"


def test_run_helper_popen_failure(monkeypatch):
    def boom(*a, **k):
        raise OSError("no sudo")

    monkeypatch.setattr(base.subprocess, "Popen", boom)
    code, out = base.run_helper("up", "wg", "home")
    assert code == 1
    assert "no sudo" in out


def test_run_helper_oserror_while_running_terminates_helper(monkeypatch):
    terminated: list[int] = []

    class BadReadProc:
        pid = 45
        returncode = 0
        stdin = None

        def poll(self):
            return 0

        @property
        def stdout(self):
            raise OSError("read failed")

    monkeypatch.setattr(base.subprocess, "Popen", lambda *a, **k: BadReadProc())
    monkeypatch.setattr(base, "terminate_registered_subprocesses", lambda: terminated.append(1))
    code, out = base.run_helper("up", "wg", "home")
    assert code == 1
    assert "read failed" in out
    assert terminated == [1]
    assert base._helper_slot[0] is None
