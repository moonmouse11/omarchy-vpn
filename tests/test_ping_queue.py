"""The panel's Ping: everything, one group, one server — and the queue."""

import fcntl
import os

import pytest

import delayping
import vpn_manager
from providers.keys import KeysProvider


class WG:
    name = "WireGuard"

    def ping_targets(self):
        return [("home", "203.0.113.5", 51820), ("work", "203.0.113.6", 51820)]


class Happ:
    name = "Happ"

    def ping_targets(self):
        return []


@pytest.fixture
def pings(monkeypatch):
    """Providers stubbed, every run recorded: (xray keys, direct names, allowed, kind)."""
    runs = []
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [Happ(), KeysProvider("vless"), WG()])
    monkeypatch.setattr(
        vpn_manager.delayping,
        "happ_targets",
        lambda sub_id=None, name=None: [
            (f"{s}\t{n}", {})
            for s, n in (("15", "DE"), ("15", "NL"), ("22", "DE"))
            if (sub_id is None or s == sub_id) and (name is None or n == name)
        ],
    )
    monkeypatch.setattr(
        vpn_manager.delayping,
        "key_targets",
        lambda kind=None, name=None: [("mykey", {})] if name in (None, "mykey") else [],
    )
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: False)
    monkeypatch.setattr(vpn_manager, "refresh_bar", lambda: None)

    def fake_run(xray, direct, allowed, kind="all", on_progress=None):
        runs.append(([k for k, _ in xray], [d[0] for d in direct], allowed, kind))
        return {k: {"ms": 100.0} for k, _ in xray} | {d[0]: {"ms": None} for d in direct}

    monkeypatch.setattr(vpn_manager.delayping, "run", fake_run)
    return runs


def _hold_ping_lock():
    """Another process measuring now (flock: per open file, so this conflicts
    within one process too)."""
    vpn_manager.PING_LOCK.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(vpn_manager.PING_LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd


# ── Scopes ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("scope", "xray", "direct"),
    [
        ({}, ["15\tDE", "15\tNL", "22\tDE", "mykey"], ["home", "work"]),
        ({"group": "happ:15:Provider A"}, ["15\tDE", "15\tNL"], []),
        ({"group": "WireGuard"}, [], ["home", "work"]),
        ({"group": "VLESS"}, ["mykey"], []),
        ({"server": ["Happ", "DE", "22"]}, ["22\tDE"], []),  # not the other subscription's DE
        ({"server": ["WireGuard", "work", ""]}, [], ["work"]),
        ({"server": ["VLESS", "mykey", ""]}, ["mykey"], []),
    ],
)
def test_a_scope_measures_exactly_its_servers(pings, scope, xray, direct):
    x, d = vpn_manager._ping_scope_targets(scope)
    assert ([k for k, _ in x], [t[0] for t in d]) == (xray, direct)


@pytest.mark.parametrize(
    ("argv", "scope"),
    [
        ([], {}),
        (["group", "happ:15:Provider A"], {"group": "happ:15:Provider A"}),
        (["server", "Happ", "🇩🇪 DE", "15"], {"server": ["Happ", "🇩🇪 DE", "15"]}),
        (["server", "WireGuard", "home"], {"server": ["WireGuard", "home", ""]}),
        (["server"], None),
        (["everything"], None),
    ],
)
def test_ping_now_arguments(argv, scope):
    assert vpn_manager._ping_scope_from_args(argv) == scope


# ── Ping all ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(("killswitch_on", "allowed"), [(True, False), (False, True)])
def test_ping_all_skips_direct_pings_under_the_killswitch(
    pings, monkeypatch, killswitch_on, allowed
):
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: killswitch_on)
    _title, text = vpn_manager.ping_now()
    assert pings == [(["15\tDE", "15\tNL", "22\tDE", "mykey"], ["home", "work"], allowed, "all")]
    assert text.startswith("4/6 servers answered")
    assert ("WireGuard/OpenVPN skipped" in text) is killswitch_on


def test_ping_all_refused_while_anything_is_measured(pings):
    fd = _hold_ping_lock()
    try:
        delayping.write_progress(1, 9, delayping.ALL)
        assert vpn_manager.ping_now()[1].startswith("Already measuring")
        delayping.write_progress(1, 9, delayping.QUEUED)
        assert vpn_manager.ping_now()[1].startswith("Wait for the queued pings")
    finally:
        os.close(fd)
    assert pings == []


def test_ping_all_drops_a_stale_queue(pings):
    """Queued scopes with no worker holding the lock: their worker died."""
    delayping.write_queue([{"group": "WireGuard"}])
    vpn_manager.ping_now()
    assert delayping.read_queue() == []
    assert len(pings) == 1


# ── The queue ────────────────────────────────────────────────────────────────


def test_single_pings_queue_behind_a_running_worker_once_each(pings):
    fd = _hold_ping_lock()
    try:
        assert vpn_manager.ping_now({"server": ["Happ", "DE", "15"]}) is None
        assert vpn_manager.ping_now({"group": "WireGuard"}) is None
        assert vpn_manager.ping_now({"server": ["Happ", "DE", "15"]}) is None  # a second click
    finally:
        os.close(fd)
    assert delayping.read_queue() == [{"server": ["Happ", "DE", "15"]}, {"group": "WireGuard"}]
    assert pings == []  # the worker measures them, not these processes


def test_the_first_single_ping_becomes_the_worker_and_drains_the_queue(pings):
    delayping.write_queue([{"group": "WireGuard"}])  # left by an earlier click
    assert vpn_manager.ping_now({"server": ["Happ", "NL", "15"]}) is None  # quiet: rows show "…"
    assert pings == [
        ([], ["home", "work"], True, "queued"),
        (["15\tNL"], [], True, "queued"),
    ]
    assert delayping.read_queue() == []


def test_single_pings_refused_while_ping_all_runs(pings):
    fd = _hold_ping_lock()
    try:
        delayping.write_progress(3, 150, delayping.ALL)
        _title, text = vpn_manager.ping_now({"server": ["Happ", "DE", "15"]})
    finally:
        os.close(fd)
    assert text.startswith("Ping all is running")
    assert delayping.read_queue() == []


def test_one_failing_scope_does_not_stall_the_queue(pings, monkeypatch):
    real = vpn_manager._measure

    def flaky(scope, kind):
        if scope == {"group": "WireGuard"}:
            raise OSError("boom")
        return real(scope, kind)

    monkeypatch.setattr(vpn_manager, "_measure", flaky)
    monkeypatch.setattr(vpn_manager.logutil, "log", lambda msg: None)
    delayping.write_queue([{"group": "WireGuard"}])
    vpn_manager.ping_now({"group": "VLESS"})
    assert [r[0] for r in pings] == [["mykey"]]
    assert delayping.read_queue() == []


# ── What the panel sees ──────────────────────────────────────────────────────


class Rows:
    def __init__(self, name, conns):
        self.name = name
        self._conns = conns

    def connections(self):
        return self._conns


@pytest.fixture
def panel(monkeypatch):
    monkeypatch.setattr(vpn_manager.happmeta, "request_subscription_update", lambda: None)
    cache: dict = {}
    monkeypatch.setattr(vpn_manager.happmeta, "_read_pings", lambda: cache)
    monkeypatch.setattr(vpn_manager.config, "load_config", vpn_manager.config.Config)
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [Rows("Happ", []), Rows("WireGuard", [])])
    monkeypatch.setattr(
        vpn_manager,
        "happ_server_groups",
        lambda provider: (
            [],
            {
                "A": [
                    {"name": "DE", "active": False, "provider_id": "15"},
                    {"name": "NL", "active": False, "provider_id": "15"},
                ],
                "B": [{"name": "DE", "active": False, "provider_id": "22"}],
            },
        ),
    )

    def pinging(**pings):
        cache.clear()
        cache.update(pings)
        return {
            (g["id"], r["name"]): r["pinging"]
            for g in vpn_manager.server_list()["groups"]
            for r in g["servers"]
        }

    return pinging


def test_queued_rows_show_as_pinging(panel):
    fd = _hold_ping_lock()  # a live worker
    try:
        delayping.write_queue([{"server": ["Happ", "DE", "22"]}, {"group": "happ:15:A"}])
        assert panel() == {
            ("happ:15:A", "DE"): True,
            ("happ:15:A", "NL"): True,
            ("happ:22:B", "DE"): True,  # its own server scope, not A's DE
        }
        delayping.write_queue([{"server": ["Happ", "DE", "22"]}])
        assert panel()[("happ:15:A", "DE")] is False
    finally:
        os.close(fd)


def test_a_stale_queue_shows_nothing(panel):
    delayping.write_queue([{"group": "happ:15:A"}])  # no worker holds the lock
    assert not any(panel().values())


def test_ping_all_shows_every_row_as_pinging(panel):
    delayping.write_progress(0, 3, delayping.ALL)
    assert all(panel().values())


def test_rows_measured_in_the_running_ping_all_show_already(panel):
    """Ping-all over 150 servers: the ones done show their result while
    the rest still say "…" — not all of them until the very end."""
    delayping.write_progress(1, 3, delayping.ALL, started=1000.0)
    state = panel(**{"15\tDE": {"ms": 90.0, "at": 1001.0}, "15\tNL": {"ms": 80.0, "at": 900.0}})
    assert state == {
        ("happ:15:A", "DE"): False,  # measured in this run
        ("happ:15:A", "NL"): True,  # only an older value: still waiting
        ("happ:22:B", "DE"): True,
    }


def test_a_queued_groups_rows_show_once_measured_but_only_in_its_own_run(panel):
    fd = _hold_ping_lock()
    try:
        delayping.write_queue([{"group": "happ:15:A"}, {"group": "happ:22:B"}])
        delayping.write_progress(1, 2, delayping.QUEUED, started=1000.0)
        state = panel(
            **{"15\tDE": {"ms": 90.0, "at": 1001.0}, "22\tDE": {"ms": 70.0, "at": 1002.0}}
        )
    finally:
        os.close(fd)
    assert state == {
        ("happ:15:A", "DE"): False,  # the running group's, measured
        ("happ:15:A", "NL"): True,
        ("happ:22:B", "DE"): True,  # its group waits in the queue: still "…"
    }


def test_the_panel_reloads_at_most_every_two_seconds_while_results_come_in(pings, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(vpn_manager.time, "monotonic", lambda: now[0])
    refreshes = []
    monkeypatch.setattr(vpn_manager, "refresh_bar", lambda: refreshes.append(1))

    def fake_run(xray, direct, allowed, kind="all", on_progress=None):
        for done, t in enumerate([0.5, 1.0, 2.5, 3.0, 4.6], start=1):
            now[0] = t
            on_progress(done, 6)
        return {}

    monkeypatch.setattr(vpn_manager.delayping, "run", fake_run)
    vpn_manager._measure({"group": "WireGuard"}, delayping.QUEUED)
    assert len(refreshes) == 2  # at 2.5 and 4.6 s; the caller refreshes at the end
