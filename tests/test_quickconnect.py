"""QUICK CONNECT: favourites, the last few servers, and the list's chips."""

import time

import pytest

import happmeta
import quickconnect
import vpn_manager
from providers.base import ActionResult, VPNConnection


def test_remember_keeps_the_newest_three_without_duplicates():
    for name in ("a", "b", "c", "a", "d"):
        quickconnect.remember("WireGuard", name)
    assert [e["name"] for e in quickconnect.load()["recent"]] == ["d", "a", "c"]


def test_forget_drops_matching_favourite_and_recent():
    quickconnect.remember("WireGuard", "home")
    quickconnect.toggle_favourite("WireGuard", "home")
    quickconnect.remember("Happ", "🇩🇪 DE", "15")
    quickconnect.forget("WireGuard", "home")
    data = quickconnect.load()
    assert data["favourites"] == []
    assert data["recent"] == [{"provider": "Happ", "name": "🇩🇪 DE", "sub_id": "15"}]
    quickconnect.forget("Happ", "🇩🇪 DE", "15")
    assert quickconnect.load()["recent"] == []


def test_toggle_favourite_stars_and_unstars():
    assert quickconnect.toggle_favourite("Happ", "🇩🇪 DE", "15") is True
    assert quickconnect.load()["favourites"] == [
        {"provider": "Happ", "name": "🇩🇪 DE", "sub_id": "15"}
    ]
    assert quickconnect.toggle_favourite("Happ", "🇩🇪 DE", "15") is False
    assert quickconnect.load()["favourites"] == []


def test_a_broken_file_reads_as_empty():
    quickconnect.QUICK_FILE.write_text("{not json")
    assert quickconnect.load() == {"favourites": [], "recent": []}
    quickconnect.QUICK_FILE.write_text('{"recent": [{"name": "no provider"}, 7]}')
    assert quickconnect.load()["recent"] == []


class FakeProvider:
    def __init__(self, name, conns=(), ok=True):
        self.name = name
        self._conns = list(conns)
        self.ok = ok

    def connections(self):
        return self._conns

    def connect(self, conn):
        return ActionResult(self.ok, "")


@pytest.mark.parametrize("ok", [True, False])
def test_only_a_successful_connect_is_remembered(monkeypatch, ok):
    home = VPNConnection(name="home", provider="WireGuard", active=False)
    wg = FakeProvider("WireGuard", [home], ok)
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg])
    monkeypatch.setattr(vpn_manager, "guarded_connect", lambda p, c: p.connect(c))
    vpn_manager.panel_connect("WireGuard", "home")
    expected = [{"provider": "WireGuard", "name": "home", "sub_id": ""}] if ok else []
    assert quickconnect.load()["recent"] == expected


def test_server_list_chips_stars_and_the_last_server(monkeypatch):
    pings = {"15\t🇩🇪 DE": {"ms": 40.0, "at": time.time()}}
    monkeypatch.setattr(happmeta, "_read_pings", lambda: pings)
    monkeypatch.setattr(happmeta, "request_subscription_update", lambda: None)
    monkeypatch.setattr(happmeta, "providers", dict)
    monkeypatch.setattr(vpn_manager.config, "load_config", vpn_manager.config.Config)
    wg = FakeProvider("WireGuard", [VPNConnection(name="home", provider="WireGuard", active=True)])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [FakeProvider("Happ"), wg])
    monkeypatch.setattr(
        vpn_manager,
        "happ_server_groups",
        lambda provider: (
            [],
            {
                "Provider A": [
                    {"name": "🇩🇪 DE", "active": False, "provider_id": "15"},
                    {"name": "🇳🇱 NL", "active": False, "provider_id": "15"},
                ]
            },
        ),
    )
    quickconnect.remember("Happ", "gone", "15")  # no longer served: no chip
    quickconnect.remember("Happ", "🇩🇪 DE", "15")
    quickconnect.remember("WireGuard", "home")
    quickconnect.toggle_favourite("Happ", "🇩🇪 DE", "15")

    listing = vpn_manager.server_list()
    quick = listing["quick"]
    assert [(c["name"], c["ping"]) for c in quick["favourites"]] == [("🇩🇪 DE", "40 ms")]
    # recent leaves the favourite out; the switch's last server is the newest
    assert [(c["name"], c["active"]) for c in quick["recent"]] == [("home", True)]
    assert quick["last"]["name"] == "home"
    sub_a = listing["groups"][0]
    assert [(r["name"], r["favourite"]) for r in sub_a["servers"]] == [
        ("🇩🇪 DE", True),
        ("🇳🇱 NL", False),
    ]


def test_favourite_flag_stars_then_refreshes_the_widget(monkeypatch):
    calls = []
    monkeypatch.setattr(vpn_manager, "refresh_bar", lambda: calls.append("refresh"))
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **kw: calls.append("notify"))
    argv = ["vpn_manager.py", "--favourite", "Happ", "🇩🇪 DE", "15"]
    monkeypatch.setattr(vpn_manager.sys, "argv", argv)
    vpn_manager.main()
    assert quickconnect.load()["favourites"] == [
        {"provider": "Happ", "name": "🇩🇪 DE", "sub_id": "15"}
    ]
    assert calls == ["refresh"]  # no bubble for a star


def test_favourite_flag_needs_happs_subscription(monkeypatch):
    monkeypatch.setattr(vpn_manager.sys, "argv", ["vpn_manager.py", "--favourite", "Happ", "x"])
    with pytest.raises(SystemExit):
        vpn_manager.main()
    assert quickconnect.load()["favourites"] == []


def test_a_star_that_cannot_be_saved_says_so(monkeypatch):
    notes = []
    monkeypatch.setattr(vpn_manager, "refresh_bar", lambda: None)
    monkeypatch.setattr(vpn_manager, "notify", lambda t, m, urgent=False: notes.append(m))

    def full_disk(*a, **kw):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(quickconnect.fsutil, "write_json_atomic", full_disk)
    argv = ["vpn_manager.py", "--favourite", "WireGuard", "home"]
    monkeypatch.setattr(vpn_manager.sys, "argv", argv)
    vpn_manager.main()
    assert notes and "No space left" in notes[0]
    quickconnect.remember("WireGuard", "home")  # a connect's remember stays silent


def test_a_second_writer_waits_for_the_lock_and_keeps_both_changes():
    """A connect's remember() and a star run in separate processes: the later
    save must not drop the earlier change (flock around read-modify-write)."""
    import fcntl
    import threading

    quickconnect.QUICK_FILE.parent.mkdir(parents=True, exist_ok=True)
    with quickconnect.QUICK_FILE.with_suffix(".lock").open("w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        writer = threading.Thread(target=quickconnect.toggle_favourite, args=("WireGuard", "a"))
        writer.start()
        writer.join(0.3)
        assert writer.is_alive()  # blocked on our lock, nothing written yet
        assert quickconnect.load()["favourites"] == []
        # meanwhile "another process" saves its change under the lock
        quickconnect.fsutil.write_json_atomic(
            quickconnect.QUICK_FILE,
            {"recent": [{"provider": "WireGuard", "name": "b", "sub_id": ""}]},
        )
    writer.join(5)
    data = quickconnect.load()
    assert [e["name"] for e in data["favourites"]] == ["a"]
    assert [e["name"] for e in data["recent"]] == ["b"]  # read after the lock: kept
