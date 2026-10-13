"""The Ping button's delay measurement through xray (delayping)."""

import json
import os
import threading
import time

import pytest

import delayping
import happmeta
import vpn_manager
from providers import happ

_SERVER = {
    "remarks": "DE",
    "outbounds": [
        {
            "protocol": "vless",
            "tag": "proxy",
            "settings": {"vnext": [{"address": "de.example.com", "port": 443, "users": []}]},
            "streamSettings": {"network": "tcp"},
        },
        {"protocol": "freedom", "tag": "direct"},
    ],
    "routing": {"rules": [{"domain": ["geosite:ru"], "outboundTag": "direct"}]},
}

_BALANCER = {
    "remarks": "Auto",
    "outbounds": [
        {
            "protocol": "vless",
            "tag": "a",
            "settings": {"vnext": [{"address": "203.0.113.1", "port": 443, "users": []}]},
        },
        {
            "protocol": "vless",
            "tag": "b",
            "settings": {"vnext": [{"address": "203.0.113.2", "port": 443, "users": []}]},
        },
        {"protocol": "freedom", "tag": "direct"},
    ],
    "routing": {
        "balancers": [{"tag": "AUTO", "selector": ["a", "b"]}],
        "rules": [{"network": "tcp,udp", "balancerTag": "AUTO"}],
    },
}


@pytest.fixture
def happ_conf(monkeypatch, tmp_path):
    path = tmp_path / "Happ.conf"
    monkeypatch.setattr(happ, "GUI_CONFIG", path)
    return path


# ── Happ's settings ──────────────────────────────────────────────────────────


def test_happs_ping_settings_are_used(happ_conf):
    happ_conf.write_text(
        "[General]\nPingSettings\\pingTestUrl=https://wrong.example/\n"
        '[Preferences]\nPingSettings\\pingTestUrl="https://cp.cloudflare.com/"\n'
        "PingSettings\\pingConcurrency=4\n"
    )
    assert delayping.test_url() == "https://cp.cloudflare.com/"
    assert delayping.concurrency() == 4


@pytest.mark.parametrize(
    ("text", "url", "workers"),
    [
        (None, delayping.DEFAULT_TEST_URL, delayping.DEFAULT_CONCURRENCY),  # no Happ.conf
        ("[Preferences]\nSubscriptions\\x=1\n", delayping.DEFAULT_TEST_URL, 8),  # never set
        (
            "[Preferences]\nPingSettings\\pingTestUrl=file:///etc/passwd\n"
            "PingSettings\\pingConcurrency=many\n",
            delayping.DEFAULT_TEST_URL,
            8,
        ),
        ("[Preferences]\nPingSettings\\pingConcurrency=500\n", delayping.DEFAULT_TEST_URL, 32),
    ],
)
def test_happs_ping_settings_fall_back(happ_conf, text, url, workers):
    if text is not None:
        happ_conf.write_text(text)
    assert delayping.test_url() == url
    assert delayping.concurrency() == workers


# ── The probe config ─────────────────────────────────────────────────────────


def test_probe_config_has_only_its_own_inbound_and_goes_straight_to_the_server():
    cfg = delayping.probe_config(happmeta.build_runtime_config(_SERVER), 41234, "wlp5s0")
    # no TUN, and not the keeper's 10808/10809 (it holds them)
    assert cfg["inbounds"] == [
        {"listen": "127.0.0.1", "port": 41234, "protocol": "http", "tag": "ping-in"}
    ]
    # the subscription's own rules (geosite:ru -> direct) don't apply
    assert cfg["routing"]["rules"][0] == {"inboundTag": ["ping-in"], "outboundTag": "proxy"}
    assert all(r.get("outboundTag") != "direct" for r in cfg["routing"]["rules"])


def test_probe_config_binds_marked_outbounds_to_the_uplink():
    """Without a TUN inbound xray has no autoOutboundsInterface: unbound, it
    would follow the default route into the running tunnel."""
    cfg = delayping.probe_config(happmeta.build_runtime_config(_SERVER), 1, "wlp5s0")
    by_tag = {o["tag"]: o for o in cfg["outbounds"]}
    for tag in ("proxy", "dns-direct"):
        sockopt = by_tag[tag]["streamSettings"]["sockopt"]
        assert sockopt == {"mark": happmeta.KILLSWITCH_MARK, "interface": "wlp5s0"}
    assert "streamSettings" not in by_tag["direct"]  # unmarked: never used, never bound
    unbound = delayping.probe_config(happmeta.build_runtime_config(_SERVER), 1, None)
    assert (
        "interface"
        not in {o["tag"]: o for o in unbound["outbounds"]}["proxy"]["streamSettings"]["sockopt"]
    )


def test_probe_of_a_balancer_server_goes_through_its_balancer():
    cfg = delayping.probe_config(happmeta.build_runtime_config(_BALANCER), 1, "eth0")
    assert cfg["routing"]["rules"][0] == {"inboundTag": ["ping-in"], "balancerTag": "AUTO"}
    assert cfg["routing"]["balancers"][0]["selector"] == ["a", "b"]


def test_probe_config_leaves_the_tunnel_config_alone():
    runtime = happmeta.build_runtime_config(_SERVER)
    before = json.dumps(runtime, sort_keys=True)
    delayping.probe_config(runtime, 1, "eth0")
    assert json.dumps(runtime, sort_keys=True) == before


# ── One probe: happd session ─────────────────────────────────────────────────


class FakeSession:
    def __init__(self, ack="started"):
        self.ack = ack
        self.sent: list[dict] = []
        self.closed = False

    def close(self):
        self.closed = True


@pytest.fixture
def happd(monkeypatch):
    """A fake happd: answers the start frame, records stops."""
    state = {"session": None, "stops": []}

    def open_session():
        state["session"] = FakeSession(state.get("ack", "started"))
        return state["session"]

    monkeypatch.setattr(happ, "_open_session", open_session)
    monkeypatch.setattr(happ, "_send_frame", lambda sock, frame: sock.sent.append(frame))
    monkeypatch.setattr(
        happ,
        "_recv_frame",
        lambda sock: {"request-id": sock.sent[-1]["request-id"], "status": sock.ack},
    )
    monkeypatch.setattr(
        happ,
        "_daemon_request",
        lambda action, **p: state["stops"].append((action, p["process-id"])) or {},
    )
    monkeypatch.setattr(happ, "_routing_asset_dir", lambda: None)
    monkeypatch.setattr(delayping, "_wait_listening", lambda port, timeout: True)
    return state


def test_probe_runs_xray_under_happd_and_always_stops_it(happd, monkeypatch):
    monkeypatch.setattr(delayping, "_request_ms", lambda port, url: 231.4)
    ms = delayping.probe("xray-ping-3", happmeta.build_runtime_config(_SERVER), "u", "eth0")
    assert ms == 231.4
    frame = happd["session"].sent[0]
    assert (frame["action"], frame["process-id"]) == ("start", "xray-ping-3")
    assert frame["executable"] == str(happ.XRAY_BIN)
    assert json.loads(frame["stdin-data"])["inbounds"][0]["tag"] == "ping-in"
    assert happd["stops"] == [("stop", "xray-ping-3")]
    assert happd["session"].closed  # happd reaps what the session started


def test_a_rejected_start_is_a_timeout_and_still_cleans_up(happd, monkeypatch):
    happd["ack"] = "error"
    monkeypatch.setattr(delayping, "_request_ms", lambda port, url: pytest.fail("no xray"))
    assert delayping.probe("xray-ping-0", happmeta.build_runtime_config(_SERVER), "u", None) is None
    assert happd["session"].closed
    assert happd["stops"] == [("stop", "xray-ping-0")]


# ── The sweep ────────────────────────────────────────────────────────────────


@pytest.fixture
def sweep(monkeypatch, tmp_path):
    monkeypatch.setattr(delayping, "PROGRESS", tmp_path / "progress.json")
    monkeypatch.setattr(happmeta, "PING_CACHE", tmp_path / "ping.json")
    monkeypatch.setattr(happmeta, "uplink_interface", lambda: "eth0")
    monkeypatch.setattr(delayping, "test_url", lambda: "https://t.example/")
    return tmp_path


def test_run_measures_every_server_and_merges_into_the_cache(sweep, monkeypatch):
    (sweep / "ping.json").write_text(json.dumps({"older": {"ms": 9.0, "at": 1.0}}))
    monkeypatch.setattr(delayping, "concurrency", lambda: 2)
    seen = []

    def fake_probe(process_id, cfg, url, uplink):
        seen.append((process_id, uplink, url))
        return None if cfg["n"] == 2 else 100.0 * cfg["n"]

    monkeypatch.setattr(delayping, "probe", fake_probe)
    monkeypatch.setattr(happmeta, "measure_ping", lambda host, port: 12.0)
    xray = [("DE", {"n": 1}), ("NL", {"n": 2}), ("PL", {"n": 3})]
    results = delayping.run(xray, [("home", "203.0.113.5", 51820)], direct_allowed=True)
    assert {k: v["ms"] for k, v in results.items()} == {
        "DE": 100.0,
        "NL": None,
        "PL": 300.0,
        "home": 12.0,
    }
    assert {p for p, _, _ in seen} <= {"xray-ping-0", "xray-ping-1"}  # concurrency 2
    assert {(u, url) for _, u, url in seen} == {("eth0", "https://t.example/")}
    cache = json.loads((sweep / "ping.json").read_text())
    assert cache["older"] == {"ms": 9.0, "at": 1.0}  # merged, not replaced
    assert cache["PL"]["ms"] == 300.0
    assert not (sweep / "progress.json").exists()


def test_run_marks_direct_targets_skipped_when_not_allowed(sweep, monkeypatch):
    monkeypatch.setattr(happmeta, "measure_ping", lambda h, p: pytest.fail("dropped anyway"))
    results = delayping.run([], [("home", "203.0.113.5", 51820)], direct_allowed=False)
    assert results["home"]["skipped"] is True
    assert happmeta.ping_status("home") == ("skipped", None)


def test_slots_never_overlap(sweep, monkeypatch):
    """Two probes under one happd process id would replace each other."""
    monkeypatch.setattr(delayping, "concurrency", lambda: 3)
    running: set[str] = set()
    clash = []
    lock = threading.Lock()

    def fake_probe(process_id, cfg, url, uplink):
        with lock:
            if process_id in running:
                clash.append(process_id)
            running.add(process_id)
        time.sleep(0.01)
        with lock:
            running.discard(process_id)
        return 1.0

    monkeypatch.setattr(delayping, "probe", fake_probe)
    delayping.run([(str(i), {}) for i in range(12)], [], direct_allowed=True)
    assert clash == []


def test_progress_is_shown_while_running_and_gone_after(sweep, monkeypatch):
    monkeypatch.setattr(delayping, "concurrency", lambda: 1)
    shown = []

    def fake_probe(process_id, cfg, url, uplink):
        shown.append(vpn_manager.activity_text())
        return 1.0

    monkeypatch.setattr(delayping, "probe", fake_probe)
    delayping.run([("a", {}), ("b", {})], [], direct_allowed=True)
    assert shown == ["ping 0/2", "ping 1/2"]
    assert vpn_manager.activity_text() == ""


def test_a_dead_sweeps_progress_is_ignored(sweep):
    (sweep / "progress.json").write_text(json.dumps({"pid": 2**22 + 7, "done": 1, "total": 9}))
    assert delayping.read_progress() is None
    (sweep / "progress.json").write_text(json.dumps({"pid": os.getpid(), "done": 1, "total": 9}))
    assert delayping.read_progress()["total"] == 9


def test_activity_is_a_label_field_even_when_disconnected(sweep, monkeypatch):
    (sweep / "progress.json").write_text(json.dumps({"pid": os.getpid(), "done": 4, "total": 9}))
    fields = vpn_manager.label_fields([], "Not protected", [], rate="", total="", cfg=None)
    assert fields["activity"] == "ping 4/9"


def test_ping_probes_are_not_a_happ_connection(monkeypatch):
    monkeypatch.setattr(
        happ,
        "_daemon_running_processes",
        lambda fresh=False: ["xray-core", "xray-keys-vless", "xray-ping-0", "xray-ping-5"],
    )
    assert happ._happ_processes() == ["xray-core"]


def test_same_named_servers_of_two_subscriptions_get_their_own_ping(monkeypatch):
    """Two subscriptions both ship a "🇩🇪 Germany": keyed by name alone, the
    last one measured overwrote the other and both showed its number."""
    servers = [
        {"name": "🇩🇪 Germany", "provider_id": "15", "config": _SERVER},
        {"name": "🇩🇪 Germany", "provider_id": "22", "config": _SERVER},
    ]
    monkeypatch.setattr(happmeta, "all_servers", lambda allow_fetch=True: servers)
    monkeypatch.setattr(delayping.keys, "_load_servers", list)
    keys = [key for key, _cfg in delayping.xray_targets()]
    assert keys == ["15\t🇩🇪 Germany", "22\t🇩🇪 Germany"]
    pings = {keys[0]: {"ms": 40.0, "at": time.time()}, keys[1]: {"ms": 300.0, "at": time.time()}}
    monkeypatch.setattr(happmeta, "_read_pings", lambda: pings)
    rows = [
        vpn_manager._server_row({"name": "🇩🇪 Germany", "active": False, "provider_id": sub})
        for sub in ("15", "22")
    ]
    assert [r["ping"] for r in rows] == ["40 ms", "300 ms"]


def test_each_result_reaches_the_cache_as_it_arrives(sweep, monkeypatch):
    """The panel shows a server's ping while the rest are still measured,
    and a cancelled run keeps what it got."""
    monkeypatch.setattr(delayping, "concurrency", lambda: 1)
    seen_in_cache = []

    def fake_probe(process_id, cfg, url, uplink):
        seen_in_cache.append(sorted(k for k in happmeta._read_pings() if k != "updated_at"))
        return 50.0

    monkeypatch.setattr(delayping, "probe", fake_probe)
    delayping.run([("a", {}), ("b", {}), ("c", {})], [], direct_allowed=True)
    assert seen_in_cache == [[], ["a"], ["a", "b"]]
