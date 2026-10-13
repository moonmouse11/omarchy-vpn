"""One switch at a time: guarded_connect/guarded_disconnect/disconnect_all
share SWITCH_LOCK, so repeated clicks can't start parallel connects — and
the newest switch wins: it stops the one holding the lock."""

import contextlib
import fcntl
import os
import signal
import time

import pytest

import config
import vpn_manager
from providers.base import ActionResult, VPNConnection


class FakeProvider:
    def __init__(self, name, conns):
        self.name = name
        self._conns = conns
        self.connected, self.disconnected = [], []

    def connections(self):
        return self._conns

    def connect(self, conn):
        self.connected.append(conn.name)
        return ActionResult(True, f"Connected: {conn.name}")

    def disconnect(self, conn):
        self.disconnected.append(conn.name)
        conn.active = False
        return ActionResult(True, f"Disconnected: {conn.name}")


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setattr(vpn_manager.config, "load_config", config.Config)
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: False)
    monkeypatch.setattr(vpn_manager.killswitch, "mode", lambda: "off")
    monkeypatch.setattr(vpn_manager.ipv6guard, "disable", lambda: ActionResult(True, ""))
    monkeypatch.setattr(vpn_manager, "_sync_ipv6_guard", lambda: None)
    monkeypatch.setattr(vpn_manager.logutil, "log", lambda msg: None)


def _hold_lock(text):
    """Another process mid-switch: its own open file + flock."""
    fd = os.open(vpn_manager.SWITCH_LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.write(fd, text.encode())
    return fd


def test_a_holder_that_is_not_a_switch_process_is_not_touched(env, monkeypatch):
    """No pid in the lock (or not our program): refuse, never signal it."""
    nl = VPNConnection(name="nl", provider="WireGuard", active=False)
    wg = FakeProvider("WireGuard", [nl])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg])
    fd = _hold_lock("connecting to Happ: 🇩🇪 Germany 1")
    try:
        result = vpn_manager.guarded_connect(wg, nl)
    finally:
        os.close(fd)
    assert not result.success
    assert "Already switching (connecting to Happ: 🇩🇪 Germany 1)" in result.message
    assert wg.connected == []  # nothing touched


@pytest.mark.parametrize("call", ["disconnect", "disconnect_all"])
def test_disconnects_wait_their_turn_too(env, monkeypatch, call):
    nl = VPNConnection(name="nl", provider="WireGuard", active=True)
    wg = FakeProvider("WireGuard", [nl])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg])
    fd = _hold_lock("connecting to x")
    try:
        if call == "disconnect":
            result = vpn_manager.guarded_disconnect(wg, nl)
        else:
            result = vpn_manager.disconnect_all()
    finally:
        os.close(fd)
    assert not result.success
    assert wg.disconnected == []


def test_lock_is_free_again_after_a_switch(env, monkeypatch):
    nl = VPNConnection(name="nl", provider="WireGuard", active=False)
    de = VPNConnection(name="de", provider="WireGuard", active=False)
    wg = FakeProvider("WireGuard", [nl, de])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg])
    assert vpn_manager.guarded_connect(wg, nl).success
    assert vpn_manager.guarded_connect(wg, de).success
    assert wg.connected == ["nl", "de"]


def test_connect_tearing_down_the_others_does_not_lock_itself_out(env, monkeypatch):
    """guarded_connect disconnects other tunnels under its own lock — the
    inner teardown must not try to take the lock again."""
    up = VPNConnection(name="old", provider="WireGuard", active=True)
    target = VPNConnection(name="new", provider="WireGuard", active=False)
    wg = FakeProvider("WireGuard", [up, target])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg])
    result = vpn_manager.guarded_connect(wg, target)
    assert result.success
    assert (wg.disconnected, wg.connected) == (["old"], ["new"])


def test_a_dead_holder_leaves_no_stale_lock(env, monkeypatch):
    """flock dies with its holder: a closed (crashed) holder frees it."""
    nl = VPNConnection(name="nl", provider="WireGuard", active=False)
    wg = FakeProvider("WireGuard", [nl])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg])
    os.close(_hold_lock("connecting to x"))  # the file stays, the lock doesn't
    assert vpn_manager.SWITCH_LOCK.exists()
    assert vpn_manager.guarded_connect(wg, nl).success


def _fork_holder(ignore_term=False):
    """A real other process mid-switch, holding the lock the way switch_lock does."""
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:  # child: hold the lock until killed
        try:
            if ignore_term:
                signal.signal(signal.SIGTERM, signal.SIG_IGN)  # stuck in getaddrinfo
            fd = os.open(vpn_manager.SWITCH_LOCK, os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            os.write(fd, f"{os.getpid()}\nconnecting to Happ: 🇩🇪 Германия".encode())
            os.write(write_end, b"x")
            while True:
                time.sleep(1)
        finally:
            os._exit(0)
    os.close(write_end)
    os.read(read_end, 1)  # the child holds the lock now
    os.close(read_end)
    return pid


# the child only makes raw os calls before os._exit, so threads left over
# from other tests (resolver daemons) can't deadlock it
@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded:DeprecationWarning")
@pytest.mark.parametrize("ignore_term", [False, True], ids=["sigterm", "needs-sigkill"])
def test_a_new_switch_supersedes_a_hung_one(env, monkeypatch, ignore_term):
    """The user's click wins: a connect stuck on a dead server used to keep
    every later click at "Already switching" — even Disconnect."""
    monkeypatch.setattr(vpn_manager, "_our_process", lambda pid, flags=None: True)
    monkeypatch.setattr(vpn_manager, "PREEMPT_GRACE", 0.3)
    up = VPNConnection(name="de", provider="WireGuard", active=True)
    wg = FakeProvider("WireGuard", [up])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg])
    pid = _fork_holder(ignore_term)
    try:
        result = vpn_manager.guarded_disconnect(wg, up)
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    assert result.success
    assert wg.disconnected == ["de"]


def test_a_superseded_switch_unwinds_quietly(env, monkeypatch):
    """The holder's side: SIGTERM mid-connect raises SwitchCancelled, which
    no `except Exception` in a provider can swallow; the result is silent
    (the newer switch reports) and the old SIGTERM handler is back."""

    class Hung(FakeProvider):
        def connect(self, conn):
            try:
                os.kill(os.getpid(), signal.SIGTERM)  # the newer switch's _preempt
                time.sleep(5)
            except Exception:  # noqa: BLE001 — the point: this must not catch it
                return ActionResult(True, "swallowed")
            return ActionResult(True, "not cancelled")

    nl = VPNConnection(name="nl", provider="WireGuard", active=False)
    wg = Hung("WireGuard", [nl])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg])
    before = signal.getsignal(signal.SIGTERM)
    result = vpn_manager.guarded_connect(wg, nl)
    assert (result.success, result.message) == (False, "")
    assert signal.getsignal(signal.SIGTERM) == before
    assert vpn_manager.guarded_connect(FakeProvider("WireGuard", [nl]), nl).success  # lock free


def test_a_nested_lock_in_the_same_process_never_signals_itself(env, monkeypatch):
    monkeypatch.setattr(vpn_manager, "_our_process", lambda pid, flags=None: True)
    killed = []
    monkeypatch.setattr(vpn_manager.os, "kill", lambda pid, sig: killed.append(pid))
    with (
        vpn_manager.switch_lock("outer"),
        pytest.raises(vpn_manager.SwitchBusy),
        vpn_manager.switch_lock("inner"),
    ):
        pass
    assert killed == []


def test_a_switch_aborts_the_checks_of_the_connection_being_left(env, monkeypatch):
    proc = vpn_manager.PROC
    script = "/home/u/.local/share/omarchy-vpn/src/vpn_manager.py"
    for pid, argv in {
        "101": ["python3", script, "--dns-autotest"],
        "102": ["python3", script, "--update-ip", "🇩🇪 DE"],
        "103": ["python3", script, "--dns-leak-test"],
        "104": ["python3", script, "--update-ping"],
        "105": ["python3", script, "--happ-keeper", "🇩🇪 DE", "15"],  # the tunnel itself
        "106": ["python3", script, "--update-subs"],
        "107": ["python3", "other.py", "--update-ip", "x"],
        str(os.getpid()): ["python3", script, "--update-ip", "me"],
    }.items():
        (proc / pid).mkdir(parents=True)
        (proc / pid / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
    (proc / "self").mkdir()
    killed = []
    monkeypatch.setattr(
        vpn_manager.os,
        "kill",
        lambda pid, sig: killed.append(pid) if sig == signal.SIGTERM else None,
    )
    with vpn_manager.switch_lock("connecting to x"):
        pass
    assert sorted(killed) == [101, 102, 103, 104]
