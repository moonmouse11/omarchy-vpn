from providers import warp

DAEMON_DOWN = (
    "Unable to connect to the CloudflareWARP daemon: No such file or directory (os error 2)"
    "\n\nMaybe the daemon is not running?\n"
)


def _present(monkeypatch, out="Status update: Disconnected\nSuccess\n", rc=0):
    monkeypatch.setattr(warp.shutil, "which", lambda _: "/usr/bin/warp-cli")
    monkeypatch.setattr(warp, "_run", lambda args, timeout=15: (rc, out))


def test_unavailable_without_binary(monkeypatch):
    monkeypatch.setattr(warp.shutil, "which", lambda _: None)
    assert warp.WarpProvider().connections() == []


def test_lists_single_row_disconnected(monkeypatch):
    _present(monkeypatch)
    conns = warp.WarpProvider().connections()
    assert [c.name for c in conns] == ["Cloudflare WARP"]
    assert conns[0].provider == "Cloudflare WARP"
    assert not conns[0].active
    assert conns[0].interface is None


def test_active_row_when_connected(monkeypatch):
    _present(monkeypatch, "Status update: Connected\nSuccess\n")
    conns = warp.WarpProvider().connections()
    assert conns[0].active
    assert conns[0].interface == "CloudflareWARP"


def test_old_style_status_line(monkeypatch):
    _present(monkeypatch, "Disconnected\n")
    assert not warp.WarpProvider().connections()[0].active
    _present(monkeypatch, "Connected\n")
    assert warp.WarpProvider().connections()[0].active


def test_never_reads_disconnected_as_connected(monkeypatch):
    _present(monkeypatch, "Status update: Disconnected\nSuccess\n")
    assert warp.WarpProvider().active_connections() == []


def test_daemon_down_lists_no_rows(monkeypatch):
    _present(monkeypatch, DAEMON_DOWN, rc=1)
    assert warp.WarpProvider().connections() == []
    assert warp.WarpProvider().active_connections() == []


def test_active_connections_is_a_single_status_call(monkeypatch):
    calls = []
    monkeypatch.setattr(warp.shutil, "which", lambda _: "/usr/bin/warp-cli")
    monkeypatch.setattr(
        warp, "_run", lambda args, timeout=15: calls.append(args) or (0, "Connected\n")
    )
    assert len(warp.WarpProvider().active_connections()) == 1
    assert calls == [["status"]]


def _conn():
    from providers.base import VPNConnection

    return VPNConnection(name="Cloudflare WARP", provider="Cloudflare WARP", active=False)


def _cli(
    monkeypatch,
    status="Status update: Disconnected\n",
    registered=True,
    connect=(0, "Success"),
    disconnect=(0, "Success"),
):
    monkeypatch.setattr(warp.shutil, "which", lambda _: "/usr/bin/warp-cli")

    def fake_run(args, timeout=15):
        if args == ["status"]:
            return (0, status) if status is not None else (1, DAEMON_DOWN)
        if args == ["registration", "show"]:
            return (0, "Registration: abc123") if registered else (1, "Error: not registered")
        if args == ["connect"]:
            return connect
        if args == ["disconnect"]:
            return disconnect
        return 1, "unexpected: " + " ".join(args)

    monkeypatch.setattr(warp, "_run", fake_run)


def test_connect_refuses_when_daemon_down(monkeypatch):
    _cli(monkeypatch, status=None)
    r = warp.WarpProvider().connect(_conn())
    assert not r.success
    assert "warp-svc.service" in r.message


def test_connect_refuses_when_not_registered(monkeypatch):
    _cli(monkeypatch, registered=False)
    r = warp.WarpProvider().connect(_conn())
    assert not r.success
    assert "warp-cli registration new" in r.message


def test_registration_show_rc0_with_error_text_counts_unregistered(monkeypatch):
    # observed on 2026.8: daemon-down `registration show` exits 0 with the error text
    monkeypatch.setattr(warp.shutil, "which", lambda _: "/usr/bin/warp-cli")

    def fake_run(args, timeout=15):
        if args == ["registration", "show"]:
            return 0, DAEMON_DOWN
        return 0, "Status update: Disconnected\n"

    monkeypatch.setattr(warp, "_run", fake_run)
    r = warp.WarpProvider().connect(_conn())
    assert not r.success
    assert "registration" in r.message


def test_connect_success(monkeypatch):
    monkeypatch.setattr(warp.time, "sleep", lambda _: None)
    _cli_seq(monkeypatch, ["Status update: Disconnected\n", "Status update: Connected\n"])
    r = warp.WarpProvider().connect(_conn())
    assert r.success


def test_connect_failure_passes_stderr(monkeypatch):
    _cli(monkeypatch, connect=(1, "Error: network unreachable"))
    r = warp.WarpProvider().connect(_conn())
    assert not r.success
    assert "network unreachable" in r.message


def test_connect_timeout_fails_fast(monkeypatch):
    monkeypatch.setattr(warp.shutil, "which", lambda _: "/usr/bin/warp-cli")

    def raising(*a, **kw):
        raise warp.subprocess.TimeoutExpired(cmd="warp-cli", timeout=15)

    monkeypatch.setattr(warp.subprocess, "run", raising)
    # shim._run unpatched → impl._run must turn the timeout into a refusal
    r = warp.WarpProvider().connect(_conn())
    assert not r.success
    assert "timeout" in r.message.lower()


def test_disconnect_success_and_failure(monkeypatch):
    _cli(monkeypatch, status="Status update: Connected\n")
    assert warp.WarpProvider().disconnect(_conn()).success
    _cli(monkeypatch, status="Status update: Connected\n", disconnect=(1, "Error: not connected"))
    r = warp.WarpProvider().disconnect(_conn())
    assert not r.success
    assert "not connected" in r.message


def test_setup_issue_binary_missing(monkeypatch):
    monkeypatch.setattr(warp.shutil, "which", lambda _: None)
    issue = warp.WarpProvider().setup_issue()
    assert issue is not None
    assert "cloudflare-warp-bin" in issue["command"]
    assert issue["hint"]


def test_setup_issue_daemon_down(monkeypatch):
    _cli(monkeypatch, status=None)
    issue = warp.WarpProvider().setup_issue()
    assert "systemctl enable --now warp-svc" in issue["command"]
    assert "registration new" in issue["command"]


def test_setup_issue_unregistered(monkeypatch):
    _cli(monkeypatch, registered=False)
    issue = warp.WarpProvider().setup_issue()
    assert issue["command"] == "warp-cli registration new"


def test_setup_issue_none_when_ready(monkeypatch):
    _cli(monkeypatch)
    assert warp.WarpProvider().setup_issue() is None


def test_label_not_duplicated_when_name_equals_provider():
    from providers.base import VPNConnection

    c = VPNConnection(name="Cloudflare WARP", provider="Cloudflare WARP", active=True)
    assert c.label == "Cloudflare WARP"


def test_not_connected_status_is_not_connected(monkeypatch):
    _present(monkeypatch, "Status update: Not Connected\n")
    assert warp.WarpProvider().active_connections() == []


def _cli_seq(monkeypatch, statuses, connect=(0, "Success")):
    """status answers cycle through `statuses`, then repeat the last one."""
    calls = {"disconnect": 0}
    monkeypatch.setattr(warp.shutil, "which", lambda _: "/usr/bin/warp-cli")
    state = {"i": 0}

    def fake_run(args, timeout=15):
        if args == ["status"]:
            s = statuses[min(state["i"], len(statuses) - 1)]
            state["i"] += 1
            return 0, s
        if args == ["registration", "show"]:
            return 0, "Registration: abc123"
        if args == ["connect"]:
            return connect
        if args == ["disconnect"]:
            calls["disconnect"] += 1
            return 0, "Success"
        return 1, "unexpected"

    monkeypatch.setattr(warp, "_run", fake_run)
    return calls


def test_connect_waits_until_connected(monkeypatch):
    monkeypatch.setattr(warp.time, "sleep", lambda _: None)
    _cli_seq(
        monkeypatch,
        [
            "Status update: Disconnected\n",
            "Status update: Connecting\n",
            "Status update: Connected\n",
        ],
    )
    r = warp.WarpProvider().connect(_conn())
    assert r.success


def test_connect_fails_when_stuck_connecting(monkeypatch):
    monkeypatch.setattr(warp.time, "sleep", lambda _: None)
    clock = {"t": 0.0}

    def monotonic():  # jump 5 s per call: the 20 s deadline passes in 5 polls
        clock["t"] += 5.0
        return clock["t"]

    monkeypatch.setattr(warp.time, "monotonic", monotonic)
    calls = _cli_seq(monkeypatch, ["Status update: Connecting\n"])
    r = warp.WarpProvider().connect(_conn())
    assert not r.success
    assert "did not connect" in r.message
    assert calls["disconnect"] == 1  # leaves no half-up Connecting state behind


def test_connect_fails_fast_on_unable(monkeypatch):
    monkeypatch.setattr(warp.time, "sleep", lambda _: None)
    _cli_seq(
        monkeypatch,
        ["Status update: Disconnected\n", "Status update: Unable to connect\nReason: No network\n"],
    )
    r = warp.WarpProvider().connect(_conn())
    assert not r.success
    assert "Unable to connect" in r.message
