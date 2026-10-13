import json
import subprocess
import time
from pathlib import Path

import pytest

import killswitch
import providers.base as base
from providers.base import ActionResult, human_bytes, iface_traffic


def test_human_bytes():
    assert human_bytes(0) == "0 B"
    assert human_bytes(512) == "512 B"
    assert human_bytes(2048) == "2.0 KiB"
    assert human_bytes(5 * 1024**3) == "5.0 GiB"


IP_S_LINK = """\
2: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN
    link/none
    RX: bytes  packets  errors  dropped missed  mcast
    123456     1000     0       0       0       0
    TX: bytes  packets  errors  dropped missed  collisions carrier
    654321     2000     0       0       0       0          0
"""


def test_iface_traffic_parses(monkeypatch):
    class Result:
        returncode = 0
        stdout = IP_S_LINK

    monkeypatch.setattr(base.subprocess, "run", lambda *a, **k: Result())
    assert iface_traffic("wg0") == "↓ 120.6 KiB  ↑ 639.0 KiB"


def test_iface_traffic_missing(monkeypatch):
    class Result:
        returncode = 1
        stdout = ""

    monkeypatch.setattr(base.subprocess, "run", lambda *a, **k: Result())
    assert iface_traffic("nope") is None


def test_iface_rate_from_cached_sample(monkeypatch, tmp_path):
    cache = tmp_path / "rate.json"
    monkeypatch.setattr(base, "RATE_CACHE", cache)
    cache.write_text(json.dumps({"wg0": {"rx": 1000, "tx": 500, "at": time.time() - 3}}))
    # 3 s later: +6144 rx bytes, +1536 tx bytes -> 2048 B/s and 512 B/s
    monkeypatch.setattr(base, "_iface_counters", lambda iface: (7144, 2036))
    rate = base.iface_rate("wg0")
    assert "↓ 2.0 KiB/s" in rate and "↑ 512 B/s" in rate


def test_iface_rate_none_without_predecessor_or_on_reset(monkeypatch, tmp_path):
    cache = tmp_path / "rate.json"
    monkeypatch.setattr(base, "RATE_CACHE", cache)
    monkeypatch.setattr(base, "_iface_counters", lambda iface: (100, 100))
    assert base.iface_rate("wg0") is None  # no cache at all
    cache.write_text(json.dumps({"wg0": {"rx": 1000, "tx": 1000, "at": time.time() - 3}}))
    assert base.iface_rate("wg0") is None  # counters reset (delta negative)
    cache.write_text(json.dumps({"wg0": {"rx": 100, "tx": 100, "at": time.time() - 3}}))
    assert base.iface_rate("wg0") is None  # no traffic in the window


def test_sample_iface_traffic_writes_counters(monkeypatch, tmp_path):
    cache = tmp_path / "rate.json"
    monkeypatch.setattr(base, "RATE_CACHE", cache)
    monkeypatch.setattr(base, "_iface_counters", lambda iface: (4096, 2048))
    base.sample_iface_traffic("wg0")
    entry = json.loads(cache.read_text())["wg0"]
    assert entry["rx"] == 4096 and entry["tx"] == 2048 and entry["at"] > 0


def test_is_enabled_probes_via_script(monkeypatch):
    """Unprivileged nft can't list tables and sudoers has no nft rule, so
    is_enabled must shell out to the script's 'is-on' and map its rc."""
    ran = []

    class Result:
        def __init__(self, rc):
            self.returncode = rc

    calls = {"n": 0}

    def fake_run(cmd, **kwargs):
        ran.append(cmd)
        calls["n"] += 1
        return Result(0 if calls["n"] == 1 else 1)

    monkeypatch.setattr(killswitch.subprocess, "run", fake_run)
    assert killswitch.is_enabled()
    assert ran == [["sudo", "-n", killswitch.SCRIPT, "is-on"]]
    assert not killswitch.is_enabled()


def test_set_mode_persists(monkeypatch, tmp_path):
    monkeypatch.setattr(killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(killswitch, "is_enabled", lambda: False)
    calls = []
    monkeypatch.setattr(
        killswitch, "_sudo", lambda *args: calls.append(args) or ActionResult(True, "ok")
    )

    assert killswitch.set_mode(True).success
    assert calls == [("detect",), ("on",)]  # enable re-detects Happ server IPs first
    assert killswitch.mode() == "all"  # the menu toggle means "all providers"

    calls.clear()
    assert killswitch.set_mode(False).success
    assert calls == [("off",)]
    assert killswitch.mode() == "off"


def test_enable_all_mode_merges_endpoints_and_ifaces(monkeypatch, tmp_path):
    """'all' mode: resolved WG/OVPN IPs + tunnel ifaces reach the script as
    'on <ips…> --iface <name>…' after the Happ detect."""
    monkeypatch.setattr(killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    calls = []
    monkeypatch.setattr(
        killswitch, "_sudo", lambda *args: calls.append(args) or ActionResult(True, "ok")
    )

    result = killswitch.enable(extra_ips=["1.2.3.4", "5.6.7.8"], ifaces=["wg0", "tun*"])
    assert result.success
    assert calls == [
        ("detect",),
        ("on", "1.2.3.4", "5.6.7.8", "--iface", "wg0", "--iface", "tun*"),
    ]


def test_enable_all_mode_tolerates_detect_failure(monkeypatch, tmp_path):
    """Happ disconnected in 'all' mode: detect fails but 'on' still runs —
    the WG/OVPN whitelist is enough. In happ-only mode (extra_ips=None) a
    failed detect stays fatal."""
    monkeypatch.setattr(killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    calls = []
    monkeypatch.setattr(
        killswitch,
        "_sudo",
        lambda *args: (
            calls.append(args)
            or ActionResult(args[0] != "detect", "ok" if args[0] != "detect" else "no happ")
        ),
    )

    assert killswitch.enable(extra_ips=["1.2.3.4"]).success
    assert [c[0] for c in calls] == ["detect", "on"]

    calls.clear()
    failed = killswitch.enable()
    assert not failed.success
    assert calls == [("detect",)]  # never reached 'on'


def test_resume_for_happ_enables_in_all_mode(monkeypatch, tmp_path):
    monkeypatch.setattr(killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    cfg = killswitch.config.load_config()
    cfg.killswitch_mode = "all"
    killswitch.config.save_config(cfg)
    monkeypatch.setattr(killswitch, "is_enabled", lambda: False)
    calls = []
    monkeypatch.setattr(
        killswitch, "enable", lambda **kw: calls.append(kw) or ActionResult(True, "ok")
    )
    assert killswitch.resume_for_happ().success
    assert calls == [{}]


def test_resolve_endpoint_ips(monkeypatch):
    import socket

    def fake_getaddrinfo(host, port, family):
        if host == "dead.example":
            raise OSError("NXDOMAIN")
        if host == "v6-only.example":
            return []  # no A record — the AF_INET query comes back empty
        return [(socket.AF_INET, 0, 0, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(killswitch.socket, "getaddrinfo", fake_getaddrinfo)
    targets = [("nl", "example.com", 51820), ("de", "example.com", 51820), ("x", "dead.example", 1)]
    assert killswitch.resolve_endpoint_ips(targets) == ["93.184.216.34"]  # dedup + skip dead
    assert killswitch.resolve_endpoint_ips([("v6", "v6-only.example", 1)]) == []


def test_resolve_endpoint_ips_dead_dns_is_bounded_and_falls_back(monkeypatch):
    """A switch away from a dead tunnel resolves through it: lookups hang.
    The whole batch must give up within the timeout (it used to take ~2 min
    per host, one after another) and use the last address that worked."""
    import socket
    import threading
    import time

    monkeypatch.setattr(killswitch.logutil, "log", lambda msg: None)
    dns_alive = True
    release = threading.Event()

    def fake_getaddrinfo(host, port, family):
        if not dns_alive:
            release.wait(5)  # stuck in the resolver
            raise OSError("Temporary failure in name resolution")
        return [(socket.AF_INET, 0, 0, "", ({"a.example": "1.1.1.1"}.get(host, "2.2.2.2"), 0))]

    monkeypatch.setattr(killswitch.socket, "getaddrinfo", fake_getaddrinfo)
    targets = [("a", "a.example", 1), ("b", "b.example", 1)]
    assert killswitch.resolve_endpoint_ips(targets) == ["1.1.1.1", "2.2.2.2"]  # remembered

    dns_alive = False
    targets.append(("never", "never.example", 1))
    started = time.monotonic()
    try:
        ips = killswitch.resolve_endpoint_ips(targets, timeout=0.3)
    finally:
        release.set()
    assert time.monotonic() - started < 2  # parallel, bounded — not per host
    assert ips == ["1.1.1.1", "2.2.2.2"]  # last known; the never-resolved host is skipped


def test_resume_for_happ_extra_ips_bypass_detect(monkeypatch, tmp_path):
    """Happ connect under killswitch: the caller passes the resolved server
    IP (detect can't see the session before connect); rules rebuild around
    it whether the killswitch is already on or being enabled by mode."""
    monkeypatch.setattr(killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    calls = []
    monkeypatch.setattr(
        killswitch, "enable", lambda **kw: calls.append(kw) or ActionResult(True, "ok")
    )
    monkeypatch.setattr(killswitch, "is_enabled", lambda: True)
    assert killswitch.resume_for_happ(extra_ips=["198.51.100.30"]).success
    assert calls == [{"extra_ips": ["198.51.100.30"], "dns": None, "fresh": True}]

    monkeypatch.setattr(killswitch, "is_enabled", lambda: False)
    cfg = killswitch.config.load_config()
    cfg.killswitch_mode = "all"
    killswitch.config.save_config(cfg)
    assert killswitch.resume_for_happ(extra_ips=["198.51.100.30"]).success
    assert calls[-1] == {"extra_ips": ["198.51.100.30"], "dns": None, "fresh": True}

    cfg.killswitch_mode = "off"
    killswitch.config.save_config(cfg)
    assert killswitch.resume_for_happ(extra_ips=["198.51.100.30"]) is None


def test_suspend_for_keeps_preference(monkeypatch, tmp_path):
    monkeypatch.setattr(killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(killswitch, "disable", lambda: ActionResult(True, "ok"))
    result = killswitch.suspend_for("WireGuard")
    assert result.success
    assert "WireGuard" in result.message and "auto-resumes" in result.message
    assert killswitch.mode() == "off"  # preference untouched


def test_resume_for_happ_when_enabled(monkeypatch, tmp_path):
    monkeypatch.setattr(killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(killswitch, "is_enabled", lambda: True)
    calls = []
    monkeypatch.setattr(
        killswitch, "redetect", lambda: calls.append("redetect") or ActionResult(True, "ok")
    )
    assert killswitch.resume_for_happ().success
    assert calls == ["redetect"]


def test_resume_for_happ_mode_off_noop(monkeypatch, tmp_path):
    monkeypatch.setattr(killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(killswitch, "is_enabled", lambda: False)
    assert killswitch.resume_for_happ() is None


def test_enable_fresh_skips_detect_and_saved_ips(monkeypatch):
    """Known server IPs: no `detect` (it scrapes every TCP session on the
    physical NIC — direct-routed sites included) and no merging of the saved
    conf (IPs of whatever server was detected last time)."""
    calls = []
    monkeypatch.setattr(killswitch, "_sudo", lambda *a: calls.append(a) or ActionResult(True, "ok"))
    assert killswitch.enable(extra_ips=["1.2.3.4"], fresh=True).success
    assert calls == [("on", "--no-conf", "1.2.3.4")]


def test_resume_for_happ_unresolved_server_keeps_detect_path(monkeypatch, tmp_path):
    # empty list = the caller couldn't resolve the server: nothing to be fresh with
    monkeypatch.setattr(killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    calls = []
    monkeypatch.setattr(
        killswitch, "enable", lambda **kw: calls.append(kw) or ActionResult(True, "ok")
    )
    monkeypatch.setattr(killswitch, "is_enabled", lambda: True)
    killswitch.resume_for_happ(extra_ips=[])
    assert calls == [{"extra_ips": [], "dns": None}]


def test_script_accepts_xray_mark_and_no_conf():
    """The nft ruleset must accept exactly the mark build_runtime_config puts
    on xray's proxy outbounds, and `on` must support --no-conf."""
    from pathlib import Path

    import happmeta

    script = (Path(__file__).resolve().parent.parent / "scripts/happ-killswitch").read_text()
    assert f"XRAY_MARK={happmeta.KILLSWITCH_MARK:#x}\n" in script
    assert "meta mark $XRAY_MARK accept" in script
    assert "--no-conf)" in script


# conftest swaps the shared subprocess.run for a fake once tests start; the
# script tests below need the real one (bash only — `rules` applies nothing)
_REAL_RUN = subprocess.run
_REAL_POPEN = subprocess.Popen  # run() spawns through it; conftest sets it to None
_SCRIPT = Path(__file__).resolve().parent.parent / "scripts/happ-killswitch"


@pytest.fixture
def real_subprocess(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", _REAL_POPEN)


def _rules(*args: str, home: str = "/nonexistent", **env: str) -> str:
    result = _REAL_RUN(
        ["bash", str(_SCRIPT), "rules", *args],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": home, "CGROUP_ROOT": "/nonexistent", **env},
        check=True,
    )
    return result.stdout


def test_ruleset_replaces_the_table_in_one_transaction(real_subprocess):
    """add + delete + define in one `nft -f` file: a rebuild (every server
    switch) never leaves a moment without rules, as the old delete-then-load
    pair did."""
    lines = _rules("198.51.100.30", "--no-conf").splitlines()
    assert lines[:3] == [
        "table inet happ-ks",
        "delete table inet happ-ks",
        "table inet happ-ks {",
    ]


def test_dns_leaves_only_to_the_given_resolvers(real_subprocess):
    """No more port 53 to anywhere: only --dns resolvers (during a connect)."""
    strict = _rules("198.51.100.30", "--no-conf")
    assert "dport 53" not in strict
    hole = _rules("198.51.100.30", "--no-conf", "--dns", "192.0.2.53", "--dns", "2001:db8::53")
    assert "ip daddr 192.0.2.53 udp dport 53 accept" in hole
    assert "ip daddr 192.0.2.53 tcp dport { 53, 853 } accept" in hole
    assert "ip6 daddr 2001:db8::53 udp dport 53 accept" in hole
    # nothing else opens DNS (the other dport is DHCP's 67)
    assert hole.count("dport 53") + hole.count("dport { 53, 853 }") == 4


def test_ruleset_rejects_what_is_not_an_address(real_subprocess):
    for bad in (["1.2.3.4; flush ruleset", "--no-conf"], ["1.2.3.4", "--no-conf", "--dns", "x"]):
        result = _REAL_RUN(
            ["bash", str(_SCRIPT), "rules", *bad],
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
            check=False,
        )
        assert result.returncode != 0
        assert "table" not in result.stdout


def test_enable_passes_dns_resolvers_to_the_script(monkeypatch):
    calls = []
    monkeypatch.setattr(killswitch, "_sudo", lambda *a: calls.append(a) or ActionResult(True, ""))
    monkeypatch.setattr(killswitch, "system_resolvers", lambda: ["192.0.2.1"])
    killswitch.enable(extra_ips=["1.2.3.4"], ifaces=["wg0"], fresh=True, dns=["192.0.2.53"])
    assert calls == [
        (
            "on",
            "--no-conf",
            "1.2.3.4",
            "--iface",
            "wg0",
            "--dns",
            "192.0.2.53",
            "--happd-dns",
            "192.0.2.1",
        )
    ]


def test_every_load_lets_happd_resolve(monkeypatch):
    """Not only during a connect: xray resolves a hostname server again on
    every reconnect and balancer pick, through its unmarked `direct`."""
    calls = []
    monkeypatch.setattr(killswitch, "_sudo", lambda *a: calls.append(a) or ActionResult(True, ""))
    monkeypatch.setattr(killswitch, "system_resolvers", lambda: ["8.8.8.8"])
    killswitch.enable(extra_ips=["1.2.3.4"], fresh=True)
    assert calls[-1][-2:] == ("--happd-dns", "8.8.8.8")
    assert "--dns" not in calls[-1]


def test_system_resolvers_from_resolv_conf(monkeypatch, tmp_path):
    conf = tmp_path / "resolv.conf"
    conf.write_text(
        "# generated\nnameserver 1.1.1.1\nnameserver 2606:4700:4700::1111\n"
        "nameserver fe80::1%wlp5s0\noptions edns0\nnameserver 1.1.1.1\n"
    )
    monkeypatch.setattr(killswitch, "RESOLV_CONF", conf)
    assert killswitch.system_resolvers() == ["1.1.1.1", "2606:4700:4700::1111", "fe80::1"]


def test_system_resolvers_behind_the_systemd_stub(monkeypatch, tmp_path):
    """resolv.conf -> 127.0.0.53: the real upstreams come from resolvectl."""
    conf = tmp_path / "resolv.conf"
    conf.write_text("nameserver 127.0.0.53\noptions edns0 trust-ad\n")
    monkeypatch.setattr(killswitch, "RESOLV_CONF", conf)

    class Out:
        stdout = (
            "Global: 1.1.1.1#cloudflare-dns.com 2606:4700:4700::1111#cloudflare-dns.com\n"
            "Link 2 (enp3s0):\n"
            "Link 3 (wlp5s0): 192.168.1.1\n"
        )

    ran = []
    monkeypatch.setattr(killswitch.subprocess, "run", lambda cmd, **kw: ran.append(cmd) or Out())
    assert killswitch.system_resolvers() == ["1.1.1.1", "2606:4700:4700::1111", "192.168.1.1"]
    assert ran == [["resolvectl", "dns"]]


def test_ruleset_accepts_wg_quick_interface_names(real_subprocess):
    """Review: wg-quick allows `=` and `+` ([a-zA-Z0-9_=+.-]{1,15})."""
    assert 'oifname "home+nl"' in _rules("1.2.3.4", "--no-conf", "--iface", "home+nl")


def test_resolve_cached_only_never_looks_up(monkeypatch):
    monkeypatch.setattr(
        killswitch.socket, "getaddrinfo", lambda *a: (_ for _ in ()).throw(AssertionError("DNS"))
    )
    killswitch.fsutil.write_json_atomic(killswitch.RESOLVED_CACHE, {"a.example": "192.0.2.1"})
    targets = [("a", "a.example", 1), ("b", "b.example", 1), ("c", "198.51.100.7", 1)]
    assert killswitch.resolve_endpoint_ips(targets, cached_only=True) == [
        "192.0.2.1",
        "198.51.100.7",
    ]


def test_happd_cgroup_gets_dns_to_the_system_resolvers(real_subprocess, tmp_path):
    """Port 53 to --happd-dns resolvers for happd's cgroup only (its xray
    resolves hostname servers through the unmarked `direct`)."""
    (tmp_path / "system.slice/happd.service").mkdir(parents=True)
    rules = _rules(
        "1.2.3.4",
        "--no-conf",
        "--happd-dns",
        "8.8.8.8",
        "--happd-dns",
        "2001:4860:4860::8888",
        CGROUP_ROOT=str(tmp_path),
    )
    cgroup = 'socket cgroupv2 level 2 "system.slice/happd.service"'
    assert f"{cgroup} ip daddr 8.8.8.8 meta l4proto {{ tcp, udp }} th dport 53 accept" in rules
    assert f"{cgroup} ip6 daddr 2001:4860:4860::8888 meta l4proto" in rules
    # nothing outside that cgroup gets DNS
    assert [line for line in rules.splitlines() if "dport 53" in line and cgroup not in line] == []


def test_no_happd_cgroup_rule_without_happd(real_subprocess, tmp_path):
    """nft resolves the path at load time: a missing cgroup (happd not
    running) would fail the whole ruleset, so the rule is left out."""
    rules = _rules("1.2.3.4", "--no-conf", "--happd-dns", "8.8.8.8", CGROUP_ROOT=str(tmp_path))
    assert "cgroupv2" not in rules
    assert "ip daddr 1.2.3.4 accept" in rules


def test_happd_dns_rejects_what_is_not_an_address(real_subprocess, tmp_path):
    (tmp_path / "system.slice/happd.service").mkdir(parents=True)
    result = _REAL_RUN(
        ["bash", str(_SCRIPT), "rules", "1.2.3.4", "--no-conf", "--happd-dns", "8.8.8.8; x"],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "CGROUP_ROOT": str(tmp_path)},
        check=False,
    )
    assert result.returncode != 0
    assert "table" not in result.stdout
