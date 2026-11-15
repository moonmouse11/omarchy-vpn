import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

import config
from providers import windscribe as ws
from providers.common import interfaceclaims

_REAL_RUN = subprocess.run
_REAL_POPEN = subprocess.Popen

LOCATIONS = """\
Best Location - Empire (10 Gbps)
Canada East - Toronto - Comfort Zone (10 Gbps)
Canada East - Montreal - Old Port (10 Gbps)
US Central - Chicago - Cubby (10 Gbps)
US Central - Dallas - Ranch (Pro) (10 Gbps)
"""

STATUS_DISCONNECTED = (
    "Internet connectivity: available\nLogin state: Logged in\nFirewall state: Off\n"
    "Connect state: Disconnected\n"
)
STATUS_CONNECTED = (
    "Internet connectivity: available\nLogin state: Logged in\nFirewall state: Off\n"
    "Connect state: Connected\nLocation: Canada East - Toronto - Comfort Zone\n"
)
STATUS_LOGGED_OUT = (
    "Internet connectivity: available\nLogin state: Logged out\nFirewall state: Off\n"
)


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
        "Best Location",
        "Canada East - Toronto - Comfort Zone",
        "Canada East - Montreal - Old Port",
        "US Central - Chicago - Cubby",
        "US Central - Dallas - Ranch (Pro)",
    ]
    assert all(c.provider == "Windscribe" and not c.active for c in conns)


def test_location_parser_bounds_whitespace_backtracking(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", _REAL_POPEN)
    _REAL_RUN(
        [
            sys.executable,
            "-c",
            "from providers.vendor.windscribe import _location_rows\n"
            "row = 'Region - City - Nickname' + ' ' * 100_000 + 'not a suffix'\n"
            "assert [location.name for location in _location_rows(row)] == [row]\n",
        ],
        cwd=Path(ws.__file__).resolve().parents[1],
        timeout=5,
        check=True,
        capture_output=True,
    )


@pytest.mark.parametrize("gap", ["", " ", " \t "])
def test_location_speed_suffix_trims_only_suffix_whitespace(monkeypatch, gap):
    _present(monkeypatch, locations=f"Region - City - Nickname (Pro){gap}(10 Gbps)\t\n")
    assert [c.name for c in ws.WindscribeProvider().connections()] == [
        "Best Location",
        "Region - City - Nickname (Pro)",
    ]


def test_connected_marks_only_the_named_location(monkeypatch):
    _present(monkeypatch, status=STATUS_CONNECTED)
    monkeypatch.setattr(interfaceclaims, "get", lambda provider: "tun0")
    conns = ws.WindscribeProvider().connections()
    active = [c for c in conns if c.active]
    assert [c.name for c in active] == ["Canada East - Toronto - Comfort Zone"]
    assert active[0].interface is not None


def test_catalogue_status_snapshot_is_called_once_and_reused(monkeypatch):
    calls = []
    statuses = [
        "Login: Logged in\nConnection: Connected to Canada East - Toronto - Comfort Zone\n"
        "Protocol: WireGuard:443\nIP: 203.0.113.4 (VPN)\nFirewall: Off\nInternet: Available\n",
        STATUS_LOGGED_OUT,
    ]
    monkeypatch.setattr(ws.shutil, "which", lambda _: "/usr/bin/windscribe-cli")
    monkeypatch.setattr(interfaceclaims, "get", lambda provider: "tun-snapshot")

    def fake_run(args, timeout=15):
        calls.append(args)
        if args == ["status"]:
            return 0, statuses.pop(0)
        if args == ["locations"]:
            return 0, LOCATIONS
        return 1, "unexpected"

    monkeypatch.setattr(ws, "_run", fake_run)

    active = [
        connection for connection in ws.WindscribeProvider().connections() if connection.active
    ]

    assert calls == [["status"], ["locations"]]
    assert statuses == [STATUS_LOGGED_OUT]
    assert [
        (connection.name, connection.interface, connection.protocol) for connection in active
    ] == [("Canada East - Toronto - Comfort Zone", "tun-snapshot", "WireGuard:443")]


def test_active_connections_is_a_single_status_call(monkeypatch):
    calls = []
    monkeypatch.setattr(ws.shutil, "which", lambda _: "/usr/bin/windscribe-cli")
    monkeypatch.setattr(
        ws,
        "_run",
        lambda args, timeout=15: calls.append(args) or (0, STATUS_CONNECTED),
    )
    assert [c.name for c in ws.WindscribeProvider().active_connections()] == [
        "Canada East - Toronto - Comfort Zone"
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


@pytest.mark.parametrize("name", ["UnexpectedNotice", "", "Region -  - Nickname"])
def test_connect_rejects_malformed_location_without_vendor_action(monkeypatch, name):
    _present(monkeypatch)
    original = ws._run
    calls = []

    def record(args, timeout=15):
        calls.append(args)
        return original(args, timeout)

    monkeypatch.setattr(ws, "_run", record)
    result = ws.WindscribeProvider().connect(_conn(name))
    assert not result.success
    assert "location" in result.message.lower()
    assert not any(args[0] == "connect" for args in calls)


@pytest.mark.parametrize("label", ["UnexpectedNotice", ""])
def test_short_connected_label_does_not_crash_or_confirm_target(monkeypatch, label):
    _frozen_clock(monkeypatch)
    monkeypatch.setattr(ws.shutil, "which", lambda _: "/usr/bin/windscribe-cli")
    state = {"connecting": False, "disconnects": 0}

    def fake_run(args, timeout=15):
        if args == ["status"]:
            if state["connecting"]:
                return 0, STATUS_CONNECTED.replace("Canada East - Toronto - Comfort Zone", label)
            return 0, STATUS_DISCONNECTED
        if args[0] == "connect":
            state["connecting"] = True
            return 0, "accepted"
        if args == ["disconnect"]:
            state["connecting"] = False
            state["disconnects"] += 1
            return 0, "disconnecting"
        return 1, "unexpected"

    monkeypatch.setattr(ws, "_run", fake_run)
    result = ws.WindscribeProvider().connect(_conn("Canada East - Toronto - Comfort Zone"))
    assert not result.success
    assert state["disconnects"] == 3  # every accepted attempt is torn down


def test_connect_waits_until_connected(monkeypatch):
    _frozen_clock(monkeypatch)
    connecting = STATUS_DISCONNECTED.replace(
        "Connect state: Disconnected", "Connect state: Connecting"
    )
    _cli_seq(monkeypatch, [STATUS_DISCONNECTED, connecting, STATUS_CONNECTED])
    r = ws.WindscribeProvider().connect(_conn())
    assert r.success


def test_connect_timeout_disconnects_and_reports(monkeypatch):
    _frozen_clock(monkeypatch)
    calls = {"disconnect": 0}
    phase = {"value": "idle"}
    monkeypatch.setattr(ws.shutil, "which", lambda _: "/usr/bin/windscribe-cli")

    def fake_run(args, timeout=15):
        if args == ["status"]:
            if phase["value"] == "connecting":
                return 0, REAL_STATUS_DISCONNECTED.replace(
                    "Connect state: Disconnected", "Connect state: Connecting"
                )
            return 0, REAL_STATUS_DISCONNECTED
        if args and args[0] == "connect":
            phase["value"] = "connecting"
            return 0, ""
        if args == ["disconnect"]:
            calls["disconnect"] += 1
            phase["value"] = "idle"
            return 0, "Disconnecting"
        return 1, "unexpected"

    monkeypatch.setattr(ws, "_run", fake_run)
    r = ws.WindscribeProvider().connect(_conn())
    assert not r.success
    assert "did not connect" in r.message
    assert calls["disconnect"] == 3


def test_automatic_protocol_falls_back_from_auto_to_stealth_then_wstunnel(monkeypatch):
    _frozen_clock(monkeypatch)
    calls = []
    statuses = iter(
        [
            REAL_STATUS_DISCONNECTED,
            REAL_STATUS_DISCONNECTED.replace(
                "Connect state: Disconnected", "Connect state: Error: WireGuard unavailable"
            ),
            REAL_STATUS_DISCONNECTED,
            REAL_STATUS_DISCONNECTED.replace(
                "Connect state: Disconnected", "Connect state: Error: Stealth unavailable"
            ),
            REAL_STATUS_DISCONNECTED,
            REAL_STATUS_CONNECTED,
        ]
    )
    monkeypatch.setattr(ws.shutil, "which", lambda _: "/usr/bin/windscribe-cli")

    def fake_run(args, timeout=15):
        calls.append(args)
        if args == ["status"]:
            return 0, next(statuses)
        return 0, ""

    monkeypatch.setattr(ws, "_run", fake_run)
    r = ws.WindscribeProvider().connect(_conn("US East - New York - Empire"))
    assert r.success
    assert [call for call in calls if call[0] == "connect"] == [
        ["connect", "-n", "New York"],
        ["connect", "-n", "New York", "stealth"],
        ["connect", "-n", "New York", "wstunnel"],
    ]


def test_explicit_protocol_uses_one_attempt_and_loads_config_once(monkeypatch):
    _frozen_clock(monkeypatch)
    calls = []
    loads = []
    statuses = iter([REAL_STATUS_DISCONNECTED, REAL_STATUS_CONNECTED])
    monkeypatch.setattr(ws.shutil, "which", lambda _: "/usr/bin/windscribe-cli")
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: loads.append(True) or config.Config(windscribe_protocol="udp"),
    )

    def fake_run(args, timeout=15):
        calls.append(args)
        if args == ["status"]:
            return 0, next(statuses)
        return 0, ""

    monkeypatch.setattr(ws, "_run", fake_run)

    result = ws.WindscribeProvider().connect(_conn("US East - New York - Empire"))

    assert result.success
    assert [call for call in calls if call[0] == "connect"] == [
        ["connect", "-n", "New York", "udp"]
    ]
    assert loads == [True]


def test_configured_port_is_appended_to_explicit_protocol(monkeypatch):
    _frozen_clock(monkeypatch)
    calls = []
    statuses = iter([REAL_STATUS_DISCONNECTED, REAL_STATUS_CONNECTED])
    monkeypatch.setattr(ws.shutil, "which", lambda _: "/usr/bin/windscribe-cli")
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: config.Config(windscribe_protocol="stealth", windscribe_port="443"),
    )

    def fake_run(args, timeout=15):
        calls.append(args)
        if args == ["status"]:
            return 0, next(statuses)
        return 0, ""

    monkeypatch.setattr(ws, "_run", fake_run)

    assert ws.WindscribeProvider().connect(_conn("US East - New York - Empire")).success
    assert [call for call in calls if call[0] == "connect"] == [
        ["connect", "-n", "New York", "stealth:443"]
    ]


def test_explicit_protocol_failure_never_falls_back(monkeypatch):
    calls = []
    monkeypatch.setattr(ws.shutil, "which", lambda _: "/usr/bin/windscribe-cli")
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: config.Config(windscribe_protocol="tcp"),
    )

    def fake_run(args, timeout=15):
        calls.append(args)
        if args == ["status"]:
            return 0, REAL_STATUS_DISCONNECTED
        if args[0] == "connect":
            return 1, "TCP blocked"
        return 0, ""

    monkeypatch.setattr(ws, "_run", fake_run)

    result = ws.WindscribeProvider().connect(_conn("US East - New York - Empire"))

    assert not result.success
    assert result.message == "TCP blocked"
    assert [call for call in calls if call[0] == "connect"] == [
        ["connect", "-n", "New York", "tcp"]
    ]


def test_fallback_waits_until_previous_attempt_is_disconnected(monkeypatch):
    _frozen_clock(monkeypatch)
    calls = []
    phase = {"value": "idle", "disconnect_polls": 0}
    monkeypatch.setattr(ws.shutil, "which", lambda _: "/usr/bin/windscribe-cli")

    def fake_run(args, timeout=15):
        calls.append(args)
        if args == ["status"]:
            if phase["value"] == "idle":
                return 0, REAL_STATUS_DISCONNECTED
            if phase["value"] == "auto":
                return 0, REAL_STATUS_DISCONNECTED.replace(
                    "Connect state: Disconnected", "Connect state: Error: blocked"
                )
            if phase["value"] == "disconnecting":
                phase["disconnect_polls"] += 1
                if phase["disconnect_polls"] < 2:
                    return 0, REAL_STATUS_DISCONNECTED.replace(
                        "Connect state: Disconnected", "Connect state: Disconnecting"
                    )
                phase["value"] = "idle"
                return 0, REAL_STATUS_DISCONNECTED
            return 0, REAL_STATUS_CONNECTED
        if args == ["connect", "-n", "New York"]:
            phase["value"] = "auto"
            return 0, ""
        if args == ["connect", "-n", "New York", "stealth"]:
            if phase["value"] != "idle":
                return 1, "previous attempt still stopping"
            phase["value"] = "stealth"
            return 0, ""
        if args == ["disconnect"]:
            phase["value"] = "disconnecting"
            phase["disconnect_polls"] = 0
            return 0, "Disconnecting"
        return 1, "unexpected"

    monkeypatch.setattr(ws, "_run", fake_run)
    r = ws.WindscribeProvider().connect(_conn("US East - New York - Empire"))
    assert r.success
    disconnect_at = calls.index(["disconnect"])
    stealth_at = calls.index(["connect", "-n", "New York", "stealth"])
    assert calls[disconnect_at + 1 : stealth_at] == [["status"], ["status"]]


@pytest.mark.parametrize("previous", [None, "utun420"])
def test_fallback_stops_when_previous_attempt_never_disconnects(monkeypatch, previous):
    _frozen_clock(monkeypatch)
    calls = []
    released = []
    monkeypatch.setattr(interfaceclaims, "get", lambda provider: previous)
    monkeypatch.setattr(interfaceclaims, "release", released.append)
    monkeypatch.setattr(ws.shutil, "which", lambda _: "/usr/bin/windscribe-cli")

    def fake_run(args, timeout=15):
        calls.append(args)
        if args == ["status"]:
            if any(call == ["disconnect"] for call in calls):
                return 0, REAL_STATUS_DISCONNECTED.replace(
                    "Connect state: Disconnected", "Connect state: Disconnecting"
                )
            if any(call and call[0] == "connect" for call in calls):
                return 0, REAL_STATUS_DISCONNECTED.replace(
                    "Connect state: Disconnected", "Connect state: Error: blocked"
                )
            return 0, REAL_STATUS_DISCONNECTED
        return 0, ""

    monkeypatch.setattr(ws, "_run", fake_run)
    result = ws.WindscribeProvider().connect(_conn("US East - New York - Empire"))
    assert not result.success
    assert "did not disconnect" in result.message
    assert [call for call in calls if call and call[0] == "connect"] == [
        ["connect", "-n", "New York"]
    ]
    assert released == ([] if previous is not None else ["Windscribe"])


def test_successful_connect_claims_the_only_new_interface(monkeypatch):
    _frozen_clock(monkeypatch)
    _cli_seq(monkeypatch, [REAL_STATUS_DISCONNECTED, REAL_STATUS_CONNECTED])
    snapshots = iter([{"lo": 1}, {"lo": 1, "utun999": 2}])
    monkeypatch.setattr(ws, "_interfaces", lambda: next(snapshots))
    claimed = []

    def record_claim(provider, iface):
        claimed.append((provider, iface))

    monkeypatch.setattr(interfaceclaims, "claim", record_claim)
    monkeypatch.setattr(interfaceclaims, "release", lambda provider: None)

    assert ws.WindscribeProvider().connect(_conn("US East - New York - Empire")).success
    assert claimed == [("Windscribe", "utun999")]


def test_connect_keeps_claim_when_vendor_reuses_the_same_interface(monkeypatch):
    _frozen_clock(monkeypatch)
    _cli_seq(monkeypatch, [REAL_STATUS_DISCONNECTED, REAL_STATUS_CONNECTED])
    monkeypatch.setattr(ws, "_interfaces", lambda: {"lo": 1, "utun420": 2})
    monkeypatch.setattr(interfaceclaims, "get", lambda provider: "utun420")
    claimed = []
    released = []
    monkeypatch.setattr(interfaceclaims, "claim", lambda provider, iface: claimed.append(iface))
    monkeypatch.setattr(interfaceclaims, "release", released.append)

    assert ws.WindscribeProvider().connect(_conn("US East - New York - Empire")).success
    assert claimed == []
    assert released == []


def test_connect_keeps_existing_exact_claim_over_unrelated_new_interface(monkeypatch):
    _frozen_clock(monkeypatch)
    _cli_seq(monkeypatch, [REAL_STATUS_DISCONNECTED, REAL_STATUS_CONNECTED])
    snapshots = iter([{"lo": 1, "utun420": 2}, {"lo": 1, "utun420": 2, "unrelated0": 3}])
    monkeypatch.setattr(ws, "_interfaces", lambda: next(snapshots))
    monkeypatch.setattr(interfaceclaims, "get", lambda provider: "utun420")
    claimed = []
    monkeypatch.setattr(interfaceclaims, "claim", lambda provider, iface: claimed.append(iface))
    monkeypatch.setattr(interfaceclaims, "release", lambda provider: None)

    assert ws.WindscribeProvider().connect(_conn("US East - New York - Empire")).success
    assert claimed == []


def test_connect_reclaims_same_name_when_interface_identity_changed(monkeypatch):
    _frozen_clock(monkeypatch)
    _cli_seq(monkeypatch, [REAL_STATUS_DISCONNECTED, REAL_STATUS_CONNECTED])
    snapshots = iter([{"lo": 1, "utun420": 2}, {"lo": 1, "utun420": 3}])
    monkeypatch.setattr(ws, "_interfaces", lambda: next(snapshots))
    monkeypatch.setattr(interfaceclaims, "get", lambda provider: None)
    claimed = []
    monkeypatch.setattr(interfaceclaims, "claim", lambda provider, iface: claimed.append(iface))
    monkeypatch.setattr(interfaceclaims, "release", lambda provider: None)

    assert ws.WindscribeProvider().connect(_conn("US East - New York - Empire")).success
    assert claimed == ["utun420"]


@pytest.mark.parametrize("after", [{"lo": 1}, {"lo": 1, "utun1": 2, "tun0": 3}])
def test_connect_does_not_guess_between_zero_or_multiple_new_interfaces(monkeypatch, after):
    _frozen_clock(monkeypatch)
    _cli_seq(monkeypatch, [REAL_STATUS_DISCONNECTED, REAL_STATUS_CONNECTED])
    snapshots = iter([{"lo": 1}, after])
    monkeypatch.setattr(ws, "_interfaces", lambda: next(snapshots))
    claimed = []
    released = []

    def record_claim(provider, iface):
        claimed.append((provider, iface))

    monkeypatch.setattr(interfaceclaims, "claim", record_claim)
    monkeypatch.setattr(interfaceclaims, "release", released.append)

    assert ws.WindscribeProvider().connect(_conn("US East - New York - Empire")).success
    assert claimed == []
    assert released == ["Windscribe"]


def test_failed_connect_releases_runtime_interface_claim(monkeypatch):
    _frozen_clock(monkeypatch)
    _cli_seq(monkeypatch, [REAL_STATUS_DISCONNECTED, "Connect state: Error: blocked\n"])
    monkeypatch.setattr(ws, "_interfaces", lambda: {"lo": 1})
    released = []
    monkeypatch.setattr(interfaceclaims, "release", released.append)
    monkeypatch.setattr(interfaceclaims, "claim", lambda provider, iface: None)

    assert not ws.WindscribeProvider().connect(_conn("US East - New York - Empire")).success
    assert released[-1] == "Windscribe"


def test_connect_vendor_refusal_surfaces(monkeypatch):
    _frozen_clock(monkeypatch)
    refused = REAL_STATUS_DISCONNECTED + "Upgrade to Pro to use this location\n"
    _cli_seq(
        monkeypatch,
        [
            REAL_STATUS_DISCONNECTED,
            refused,
            REAL_STATUS_DISCONNECTED,
            refused,
            REAL_STATUS_DISCONNECTED,
            refused,
            REAL_STATUS_DISCONNECTED,
        ],
    )
    r = ws.WindscribeProvider().connect(_conn())
    assert not r.success
    assert "Upgrade to Pro" in r.message


def test_disconnect_waits_for_actual_teardown(monkeypatch):
    _frozen_clock(monkeypatch)
    statuses = iter([STATUS_CONNECTED, STATUS_DISCONNECTED])
    calls = []

    def run(args):
        calls.append(args)
        return (0, next(statuses)) if args == ["status"] else (0, "accepted")

    monkeypatch.setattr(ws, "_run", run)
    assert ws.WindscribeProvider().disconnect(_conn()).success
    assert calls == [["disconnect"], ["status"], ["status"]]


def test_disconnect_timeout_reports_failure(monkeypatch):
    _frozen_clock(monkeypatch)
    _cli_seq(monkeypatch, [STATUS_CONNECTED])
    result = ws.WindscribeProvider().disconnect(_conn())
    assert not result.success
    assert "disconnect" in result.message.lower()


def test_disconnect_success_and_failure(monkeypatch):
    released = []
    monkeypatch.setattr(interfaceclaims, "release", released.append)
    calls = _cli_seq(monkeypatch, [STATUS_DISCONNECTED])
    assert ws.WindscribeProvider().disconnect(_conn()).success
    assert calls["disconnect"] == 1
    assert released == []  # exact ownership remains until the interface disappears
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


def test_lockdown_hint_when_firewall_on(monkeypatch):
    _present(
        monkeypatch, status=STATUS_CONNECTED.replace("Firewall state: Off", "Firewall state: On")
    )
    hint = ws.WindscribeProvider().lockdown_hint(_conn())
    assert hint is not None
    assert "windscribe-cli firewall off" in hint


def test_no_lockdown_hint_when_firewall_off(monkeypatch):
    _present(monkeypatch, status=STATUS_CONNECTED)
    assert ws.WindscribeProvider().lockdown_hint(_conn()) is None


def test_real_v2_status_shape_logged_out(monkeypatch):
    """Pinned from live windscribe-cli v2.21.7: key-value status lines."""
    _present(
        monkeypatch,
        status="Internet connectivity: available\nLogin state: Logged out\nFirewall state: Off\n",
    )
    assert ws.WindscribeProvider().connections() == []
    issue = ws.WindscribeProvider().setup_issue()
    assert issue is not None
    assert issue["command"] == "windscribe-cli login"


def test_real_v2_status_shape_logged_in(monkeypatch):
    _present(
        monkeypatch,
        status=(
            "Internet connectivity: available\nLogin state: Logged in\n"
            "Firewall state: Off\nVPN state: Disconnected\n"
        ),
    )
    issue = ws.WindscribeProvider().setup_issue()
    assert issue is None


REAL_LOCATIONS = """\
Best Location - Empire (10 Gbps)
US Central - Atlanta - Magic City (Pro) (10 Gbps)
US Central - Atlanta - Peachtree (10 Gbps)
US East - Miami - Vice (10 Gbps)
US East - New York - Empire (10 Gbps)
US East - New York - Insomnia (Pro) (10 Gbps)
"""

REAL_STATUS_DISCONNECTED = (
    "Internet connectivity: available\nLogin state: Logged in\nFirewall state: Off\n"
    "Connect state: Disconnected\nData usage: 0 bytes / 2.00 GB\n"
)

REAL_STATUS_CONNECTED = (
    "Internet connectivity: available\nLogin state: Logged in\nFirewall state: Off\n"
    "Connect state: Connected\nLocation: US East - New York - Empire\n"
    "Data usage: 100.0 MB / 2.00 GB\n"
)


def test_real_locations_rows(monkeypatch):
    _present(monkeypatch, status=REAL_STATUS_DISCONNECTED, locations=REAL_LOCATIONS)
    conns = ws.WindscribeProvider().connections()
    assert [c.name for c in conns] == [
        "Best Location",
        "US Central - Atlanta - Magic City (Pro)",
        "US Central - Atlanta - Peachtree",
        "US East - Miami - Vice",
        "US East - New York - Empire",
        "US East - New York - Insomnia (Pro)",
    ]


def test_malformed_location_rows_are_rejected_but_nickname_dashes_survive():
    from providers.vendor.windscribe import _location_rows

    rows = _location_rows(
        "US East - New York\n"
        " - New York - Empire\n"
        "US East -  - Empire\n"
        "US East - New York - \n"
        "US East - New York - Empire - Extra\n"
    )

    assert [(row.region, row.city, row.nickname) for row in rows] == [
        ("US East", "New York", "Empire - Extra")
    ]


def test_duplicate_location_rows_merge_restrictive_flags_in_first_seen_order():
    from providers.vendor.windscribe import _location_rows

    rows = _location_rows(
        "Canada East - Toronto - Comfort Zone\n"
        "US East - New York - Empire\n"
        "us east - new york - empire (Disabled)\n"
        "US EAST - NEW YORK - EMPIRE (10 Gbps) (Pro)\n"
        "US West - Seattle - Cobain\n"
    )

    assert [row.name for row in rows] == [
        "Canada East - Toronto - Comfort Zone",
        "US East - New York - Empire (Pro)",
        "US West - Seattle - Cobain",
    ]
    assert (rows[1].pro, rows[1].disabled, rows[1].ten_gbps) == (True, True, True)


def test_duplicate_location_rows_keep_disabled_when_it_appears_first():
    from providers.vendor.windscribe import _location_rows

    [row] = _location_rows("US East - New York - Empire (Disabled)\nUS East - New York - Empire\n")

    assert row.disabled is True


def test_location_metadata_parser_handles_flags_duplicates_and_malformed_rows():
    from providers.vendor.windscribe import _location_rows

    rows = _location_rows(
        "Best Location - Empire (10 Gbps)\n"
        "US East - New York - Empire (Disabled) (10 Gbps) (Pro)\n"
        "US East - New York - Empire (Pro) (10 Gbps) (Disabled)\n"
        "Canada East - Toronto - Comfort Zone (10 Gbps)\n"
        "broken\n"
        "Region -  - Nickname\n"
    )

    assert [(row.name, row.region, row.city, row.nickname) for row in rows] == [
        ("US East - New York - Empire (Pro)", "US East", "New York", "Empire"),
        ("Canada East - Toronto - Comfort Zone", "Canada East", "Toronto", "Comfort Zone"),
    ]
    assert (rows[0].pro, rows[0].disabled, rows[0].ten_gbps) == (True, True, True)
    assert (rows[1].pro, rows[1].disabled, rows[1].ten_gbps) == (False, False, True)


def test_best_location_is_one_synthetic_inactive_row(monkeypatch):
    _present(monkeypatch, status=REAL_STATUS_CONNECTED, locations=REAL_LOCATIONS)

    conns = ws.WindscribeProvider().connections()

    assert [connection.name for connection in conns].count("Best Location") == 1
    best = conns[0]
    assert best.name == "Best Location"
    assert best.metadata == {"synthetic": True}
    assert best.active is False
    assert [connection.name for connection in conns if connection.active] == [
        "US East - New York - Empire"
    ]


def test_disabled_location_is_refused_without_vendor_connect(monkeypatch):
    locations = "US East - New York - Empire (Disabled) (10 Gbps)\n"
    _present(monkeypatch, status=REAL_STATUS_DISCONNECTED, locations=locations)
    provider = ws.WindscribeProvider()
    [best, disabled] = provider.connections()
    calls = []
    original = ws._run

    def record(args, timeout=15):
        calls.append(args)
        return original(args, timeout)

    monkeypatch.setattr(ws, "_run", record)
    result = provider.connect(disabled)

    assert best.name == "Best Location"
    assert disabled.metadata["disabled"] is True
    assert not result.success
    assert "disabled" in result.message.lower()
    assert not any(args[0] == "connect" for args in calls)


def test_connect_uses_city_not_ambiguous_nickname(monkeypatch):
    sent = []
    _frozen_clock(monkeypatch)
    monkeypatch.setattr(ws.shutil, "which", lambda _: "/usr/bin/windscribe-cli")

    def fake_run(args, timeout=15):
        if args == ["status"]:
            return 0, REAL_STATUS_CONNECTED
        if args and args[0] == "connect":
            sent.append(args)
            return 0, ""
        return 1, "unexpected"

    monkeypatch.setattr(ws, "_run", fake_run)
    r = ws.WindscribeProvider().connect(_conn("US East - New York - Empire"))
    assert r.success
    assert sent == [["connect", "-n", "New York"]]


def test_connect_uses_city_when_nickname_contains_location_delimiter(monkeypatch):
    sent = []
    _frozen_clock(monkeypatch)
    status = REAL_STATUS_CONNECTED.replace("Empire", "Empire - Extra")
    monkeypatch.setattr(ws.shutil, "which", lambda _: "/usr/bin/windscribe-cli")

    def fake_run(args, timeout=15):
        if args == ["status"]:
            return 0, status
        if args and args[0] == "connect":
            sent.append(args)
            return 0, ""
        return 1, "unexpected"

    monkeypatch.setattr(ws, "_run", fake_run)

    result = ws.WindscribeProvider().connect(_conn("US East - New York - Empire - Extra"))

    assert result.success
    assert sent == [["connect", "-n", "New York"]]


def test_best_location_uses_cli_best_keyword(monkeypatch):
    sent = []
    _frozen_clock(monkeypatch)
    monkeypatch.setattr(ws.shutil, "which", lambda _: "/usr/bin/windscribe-cli")

    def fake_run(args, timeout=15):
        if args == ["status"]:
            return 0, REAL_STATUS_DISCONNECTED
        if args and args[0] == "connect":
            sent.append(args)
            return 0, ""
        return 0, ""

    monkeypatch.setattr(ws, "_run", fake_run)
    ws.WindscribeProvider().connect(_conn("Best Location - Empire"))
    assert sent == [
        ["connect", "-n", "best"],
        ["connect", "-n", "best", "stealth"],
        ["connect", "-n", "best", "wstunnel"],
    ]


def test_connected_status_uses_claimed_interface_and_protocol(monkeypatch):
    status = REAL_STATUS_CONNECTED.replace(
        "Location: US East - New York - Empire\n",
        "Location: US East - New York - Empire\nProtocol: Stealth:443\n",
    )
    _present(monkeypatch, status=status, locations=REAL_LOCATIONS)
    monkeypatch.setattr(interfaceclaims, "get", lambda provider: "tun0")

    active = ws.WindscribeProvider().active_connections()
    assert len(active) == 1
    assert active[0].interface == "tun0"
    assert active[0].protocol == "Stealth:443"


def test_connected_status_omits_missing_interface_claim(monkeypatch):
    _present(monkeypatch, status=REAL_STATUS_CONNECTED, locations=REAL_LOCATIONS)
    monkeypatch.setattr(interfaceclaims, "get", lambda provider: None)
    active = ws.WindscribeProvider().active_connections()
    assert len(active) == 1
    assert active[0].interface is None


def test_real_connected_status_marks_active(monkeypatch):
    _present(monkeypatch, status=REAL_STATUS_CONNECTED, locations=REAL_LOCATIONS)
    conns = ws.WindscribeProvider().connections()
    active = [c for c in conns if c.active]
    assert [c.name for c in active] == ["US East - New York - Empire"]


def test_connect_state_error_counts_as_disconnected(monkeypatch):
    status = REAL_STATUS_DISCONNECTED.replace(
        "Connect state: Disconnected", "Connect state: Error: Location does not exist"
    )
    _present(monkeypatch, status=status, locations=REAL_LOCATIONS)
    assert ws.WindscribeProvider().active_connections() == []


def test_firewall_state_from_status_line(monkeypatch):
    status = REAL_STATUS_CONNECTED.replace("Firewall state: Off", "Firewall state: On")
    _present(monkeypatch, status=status)
    hint = ws.WindscribeProvider().lockdown_hint(_conn())
    assert hint is not None
    assert "firewall off" in hint


STATUS_2258_DISCONNECTED = (
    "Login: Logged in\nConnection: Disconnected\nFirewall: Off\n"
    "Data usage: 0 bytes / 2.00 GB\nInternet: Available\n"
)
STATUS_2258_CONNECTED = (
    "Login: Logged in\nConnection: Connected to US East - New York - Empire\n"
    "Protocol: Stealth:443\nIP: 203.0.113.4 (VPN)\nFirewall: On\n"
    "Data usage: 100.0 MB / 2.00 GB\nInternet: Available\n"
)


def test_2258_status_drives_connections_and_active_detection(monkeypatch):
    _present(monkeypatch, status=STATUS_2258_CONNECTED, locations=REAL_LOCATIONS)
    monkeypatch.setattr(interfaceclaims, "get", lambda provider: "tun0")
    provider = ws.WindscribeProvider()

    active_rows = [connection for connection in provider.connections() if connection.active]
    assert [connection.name for connection in active_rows] == ["US East - New York - Empire"]
    assert [connection.name for connection in provider.active_connections()] == [
        "US East - New York - Empire"
    ]
    assert provider.active_connections()[0].protocol == "Stealth:443"
    assert provider.setup_issue() is None
    assert "firewall off" in provider.lockdown_hint(_conn())


def test_2258_disconnected_status_is_ready_but_inactive(monkeypatch):
    _present(monkeypatch, status=STATUS_2258_DISCONNECTED, locations=REAL_LOCATIONS)
    provider = ws.WindscribeProvider()

    assert provider.setup_issue() is None
    assert provider.active_connections() == []
    assert not any(connection.active for connection in provider.connections())


def test_unknown_output_is_a_compatibility_issue_and_not_ready(monkeypatch):
    _present(monkeypatch, status="Windscribe status format changed\n")
    provider = ws.WindscribeProvider()

    issue = provider.setup_issue()
    assert "not recognized" in issue["hint"]
    assert issue["command"] == "windscribe-cli status"
    assert provider.connections() == []


def test_partially_known_future_status_fails_closed(monkeypatch):
    _present(monkeypatch, status="Login: Logged in\nConnection: Established to New York\n")
    provider = ws.WindscribeProvider()

    assert [connection.name for connection in provider.active_connections()] == [
        "Windscribe connection (status unknown)"
    ]
    assert provider.connections() == []
    result = provider.connect(_conn())
    assert not result.success
    assert "not recognized" in result.message


def test_unknown_output_blocks_connect_before_vendor_action(monkeypatch):
    _present(monkeypatch, status="Windscribe status format changed\n")
    calls = []
    original = ws._run

    def record(args, timeout=15):
        calls.append(args)
        return original(args, timeout)

    monkeypatch.setattr(ws, "_run", record)
    result = ws.WindscribeProvider().connect(_conn())

    assert not result.success
    assert "not recognized" in result.message
    assert not any(args[0] == "connect" for args in calls)


def test_unknown_output_is_conservatively_active_with_exact_claim(monkeypatch):
    _present(monkeypatch, status="Windscribe status format changed\n")
    monkeypatch.setattr(interfaceclaims, "get", lambda provider: "tun0")

    active = ws.WindscribeProvider().active_connections()

    assert [(connection.name, connection.interface) for connection in active] == [
        ("Windscribe connection (status unknown)", "tun0")
    ]


def test_unknown_output_never_confirms_disconnect(monkeypatch):
    _frozen_clock(monkeypatch)
    _cli_seq(monkeypatch, ["Windscribe status format changed\n"])

    result = ws.WindscribeProvider().disconnect(_conn())

    assert not result.success
    assert "not recognized" in result.message


def test_cli_serializes_concurrent_processes(monkeypatch, tmp_path):
    from providers.vendor import windscribe_lock

    monkeypatch.setattr(windscribe_lock, "LOCK_FILE", tmp_path / "windscribe.lock")
    first_entered = threading.Event()
    second_entered = threading.Event()
    release_first = threading.Event()
    calls = []

    def fake_run(*args, **kwargs):
        calls.append(args[0])
        if len(calls) == 1:
            first_entered.set()
            assert release_first.wait(2)
        else:
            second_entered.set()
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(ws.subprocess, "run", fake_run)
    results = []
    first = threading.Thread(target=lambda: results.append(ws._run(["status"])))
    second = threading.Thread(target=lambda: results.append(ws._run(["locations"])))
    try:
        first.start()
        assert first_entered.wait(1)
        second.start()
        assert not second_entered.wait(0.05)
    finally:
        release_first.set()
        first.join(2)
        second.join(2)

    assert second_entered.is_set()
    assert calls == [
        ["windscribe-cli", "status"],
        ["windscribe-cli", "locations"],
    ]
    assert sorted(results) == [(0, "ok"), (0, "ok")]
