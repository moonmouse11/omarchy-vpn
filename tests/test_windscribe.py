from providers import windscribe as ws

LOCATIONS = """\
Locations
---------
 Canada East
   Toronto - Comfort Zone
   Montreal - Old Port
 US Central
   Chicago - Cubby
   Dallas - Ranch
"""

STATUS_DISCONNECTED = "Windscribe: Disconnected\n"
STATUS_CONNECTED = "Windscribe: Connected to Toronto - Comfort Zone\n"
STATUS_LOGGED_OUT = "Windscribe: Disconnected\nNot logged in\n"


def _present(monkeypatch, status=STATUS_DISCONNECTED, locations=LOCATIONS, rc=0):
    monkeypatch.setattr(ws.shutil, "which", lambda _: "/usr/bin/windscribe-cli")

    def fake_run(args, timeout=15):
        if args == ["status"]:
            return rc, status
        if args == ["locations"]:
            return 0, locations
        return 1, "unexpected: " + " ".join(args)

    monkeypatch.setattr(ws, "_run", fake_run)


def test_unavailable_without_binary(monkeypatch):
    monkeypatch.setattr(ws.shutil, "which", lambda _: None)
    assert ws.WindscribeProvider().connections() == []


def test_logged_out_lists_no_rows(monkeypatch):
    _present(monkeypatch, status=STATUS_LOGGED_OUT)
    assert ws.WindscribeProvider().connections() == []


def test_unknown_status_counts_as_logged_out(monkeypatch):
    _present(monkeypatch, status="", rc=1)
    assert ws.WindscribeProvider().connections() == []


def test_lists_locations_when_disconnected(monkeypatch):
    _present(monkeypatch)
    conns = ws.WindscribeProvider().connections()
    assert [c.name for c in conns] == [
        "Toronto - Comfort Zone",
        "Montreal - Old Port",
        "Chicago - Cubby",
        "Dallas - Ranch",
    ]
    assert all(c.provider == "Windscribe" and not c.active for c in conns)


def test_connected_marks_only_the_named_location(monkeypatch):
    _present(monkeypatch, status=STATUS_CONNECTED)
    conns = ws.WindscribeProvider().connections()
    active = [c for c in conns if c.active]
    assert [c.name for c in active] == ["Toronto - Comfort Zone"]
    assert active[0].interface is not None


def test_active_connections_is_a_single_status_call(monkeypatch):
    calls = []
    monkeypatch.setattr(ws.shutil, "which", lambda _: "/usr/bin/windscribe-cli")
    monkeypatch.setattr(
        ws,
        "_run",
        lambda args, timeout=15: calls.append(args) or (0, STATUS_CONNECTED),
    )
    assert [c.name for c in ws.WindscribeProvider().active_connections()] == [
        "Toronto - Comfort Zone"
    ]
    assert calls == [["status"]]


def _conn(name="Toronto - Comfort Zone"):
    from providers.base import VPNConnection

    return VPNConnection(name=name, provider="Windscribe", active=False)


def _cli_seq(monkeypatch, statuses, connect=(0, ""), disconnect=(0, "")):
    """status answers cycle through `statuses`, then repeat the last one."""
    calls = {"disconnect": 0}
    monkeypatch.setattr(ws.shutil, "which", lambda _: "/usr/bin/windscribe-cli")
    state = {"i": 0}

    def fake_run(args, timeout=15):
        if args == ["status"]:
            s = statuses[min(state["i"], len(statuses) - 1)]
            state["i"] += 1
            return 0, s
        if args and args[0] == "connect":
            return connect
        if args == ["disconnect"]:
            calls["disconnect"] += 1
            return disconnect
        if args == ["locations"]:
            return 0, LOCATIONS
        return 1, "unexpected"

    monkeypatch.setattr(ws, "_run", fake_run)
    return calls


def _frozen_clock(monkeypatch):
    monkeypatch.setattr(ws.time, "sleep", lambda _: None)
    clock = {"t": 0.0}

    def monotonic():
        clock["t"] += 5.0
        return clock["t"]

    monkeypatch.setattr(ws.time, "monotonic", monotonic)


def test_connect_refuses_when_logged_out(monkeypatch):
    _cli_seq(monkeypatch, [STATUS_LOGGED_OUT])
    r = ws.WindscribeProvider().connect(_conn())
    assert not r.success
    assert "windscribe-cli login" in r.message


def test_connect_waits_until_connected(monkeypatch):
    _frozen_clock(monkeypatch)
    _cli_seq(monkeypatch, [STATUS_DISCONNECTED, "Windscribe: Connecting\n", STATUS_CONNECTED])
    r = ws.WindscribeProvider().connect(_conn())
    assert r.success


def test_connect_timeout_disconnects_and_reports(monkeypatch):
    _frozen_clock(monkeypatch)
    calls = _cli_seq(monkeypatch, ["Windscribe: Connecting\n"])
    r = ws.WindscribeProvider().connect(_conn())
    assert not r.success
    assert "did not connect" in r.message
    assert calls["disconnect"] == 1


def test_connect_vendor_refusal_surfaces(monkeypatch):
    _frozen_clock(monkeypatch)
    _cli_seq(
        monkeypatch,
        ["Windscribe: Disconnected\nUpgrade to Pro to use this location\n"],
    )
    r = ws.WindscribeProvider().connect(_conn())
    assert not r.success
    assert "Upgrade to Pro" in r.message


def test_disconnect_success_and_failure(monkeypatch):
    calls = _cli_seq(monkeypatch, [STATUS_CONNECTED])
    assert ws.WindscribeProvider().disconnect(_conn()).success
    assert calls["disconnect"] == 1
    _cli_seq(monkeypatch, [STATUS_CONNECTED], disconnect=(1, "Error: not connected"))
    r = ws.WindscribeProvider().disconnect(_conn())
    assert not r.success
    assert "not connected" in r.message


def test_setup_issue_binary_missing(monkeypatch):
    monkeypatch.setattr(ws.shutil, "which", lambda _: None)
    issue = ws.WindscribeProvider().setup_issue()
    assert issue is not None
    assert "windscribe-cli" in issue["command"]
    assert issue["hint"]


def test_setup_issue_logged_out(monkeypatch):
    _present(monkeypatch, status=STATUS_LOGGED_OUT)
    issue = ws.WindscribeProvider().setup_issue()
    assert issue["command"] == "windscribe-cli login"


def test_setup_issue_none_when_ready(monkeypatch):
    _present(monkeypatch)
    assert ws.WindscribeProvider().setup_issue() is None


def _firewall(monkeypatch, state):
    monkeypatch.setattr(ws.shutil, "which", lambda _: "/usr/bin/windscribe-cli")

    def fake_run(args, timeout=15):
        if args == ["firewall"]:
            return 0, f"Firewall: {state}\n"
        if args == ["status"]:
            return 0, STATUS_CONNECTED
        return 1, "unexpected"

    monkeypatch.setattr(ws, "_run", fake_run)


def test_lockdown_hint_when_firewall_on(monkeypatch):
    _firewall(monkeypatch, "On")
    hint = ws.WindscribeProvider().lockdown_hint(_conn())
    assert hint is not None
    assert "windscribe-cli firewall off" in hint


def test_no_lockdown_hint_when_firewall_off_or_auto(monkeypatch):
    _firewall(monkeypatch, "Off")
    assert ws.WindscribeProvider().lockdown_hint(_conn()) is None
    _firewall(monkeypatch, "Auto")
    assert ws.WindscribeProvider().lockdown_hint(_conn()) is None


def test_unlimited_status_is_not_a_failure(monkeypatch):
    """Pro accounts report 'Unlimited' — substring 'limit' must not kill the connect."""
    _frozen_clock(monkeypatch)
    _cli_seq(
        monkeypatch,
        [
            STATUS_DISCONNECTED,  # consumed by the login check
            "Windscribe: Disconnected\nBandwidth used: Unlimited\n",  # first poll
            STATUS_CONNECTED,
        ],
    )
    r = ws.WindscribeProvider().connect(_conn())
    assert r.success


def test_noisy_firewall_output_is_not_misread(monkeypatch):
    """'connection' contains 'on' — the firewall state word must be parsed, not scanned."""
    monkeypatch.setattr(ws.shutil, "which", lambda _: "/usr/bin/windscribe-cli")

    def fake_run(args, timeout=15):
        if args == ["firewall"]:
            return 0, "Firewall: Off\nNote: no active connection\n"
        if args == ["status"]:
            return 0, STATUS_CONNECTED
        return 1, "unexpected"

    monkeypatch.setattr(ws, "_run", fake_run)
    assert ws.WindscribeProvider().lockdown_hint(_conn()) is None
