"""Connect/disconnect orchestration, switch lock, killswitch interplay."""

import contextlib
import fcntl
import signal
from pathlib import Path

import config
import happmeta
import ipv6guard
import killswitch
import logutil
import providers.happd.happ as happ_provider
import settings_tui
from app.helpers import notify
from app.registry import _provider_pool, active_connections
from providers.base import (
    ActionResult,
    VPNConnection,
    run_helper,
    terminate_registered_subprocesses,
)
from providers.keys import KeysProvider

# ── Menu actions ──────────────────────────────────────────────────────────────


SWITCH_LOCK = Path.home() / ".cache/vpn-manager/switch.lock"
PREEMPT_GRACE = 2.0  # s for a superseded switch to stop on SIGTERM before SIGKILL
PREEMPT_WAIT = 3.0  # s more for the lock after SIGKILL
HANDOVER_WAIT = PREEMPT_GRACE + PREEMPT_WAIT  # s for a lock no switch of ours names
PROC = Path("/proc")
# background checks of the connection being left: their answers would
# describe the old server (or time out on a dead one) — killed on a switch.
# Not --update-reputation/--update-subs: those don't depend on which server is up.
CHECK_FLAGS = ("--dns-autotest", "--check", "--update-ip")


class SwitchBusy(Exception):
    """Another connect/disconnect holds SWITCH_LOCK and won't let go."""


class SwitchCancelled(BaseException):
    """This switch was superseded by a newer one (SIGTERM from its switch_lock).
    BaseException, like KeyboardInterrupt: a provider's `except Exception`
    must not swallow it and carry on connecting."""


class CheckCancelled(BaseException):
    """A DNS leak test stopped by a switch (_abort_checks)."""


def _vm():
    import vpn_manager as vm  # noqa: PLC0415 — tests patch vpn_manager.os / PROC / time

    return vm


def _vm_fn(name: str, local):
    """Use vpn_manager.<name> when tests monkeypatch it."""
    remote = getattr(_vm(), name, None)
    if remote is not None and remote is not local:
        return remote
    return local


def _lock_holder(fd: int) -> tuple[int | None, str]:
    """(pid, action) written by the holder: "PID\naction"."""
    vm_os = _vm().os
    vm_os.lseek(fd, 0, vm_os.SEEK_SET)
    text = vm_os.read(fd, 1024).decode(errors="replace").strip()
    pid_text, _, action = text.partition("\n")
    if pid_text.isdigit():
        return int(pid_text), action.strip() or "another switch"
    return None, text or "another switch"


def _our_process(pid: int, flags: tuple[str, ...] | None = None) -> bool:
    """pid is this program (vpn_manager.py), optionally run with one of flags."""
    try:
        argv = (_vm().PROC / str(pid) / "cmdline").read_bytes().split(b"\0")
    except OSError:
        return False
    args = [a.decode(errors="replace") for a in argv if a]
    script = next((i for i, a in enumerate(args) if a.endswith("vpn_manager.py")), None)
    if script is None:
        return False
    return flags is None or (len(args) > script + 1 and args[script + 1] in flags)


def _try_flock(fd: int) -> bool:
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def _wait_flock(fd: int, seconds: float) -> bool:
    vm_time = _vm().time
    deadline = vm_time.monotonic() + seconds
    while True:
        if _try_flock(fd):
            return True
        if vm_time.monotonic() >= deadline:
            return False
        vm_time.sleep(0.05)


def _child_pids(ppid: int) -> list[int]:
    children: list[int] = []
    try:
        entries = list(_vm().PROC.iterdir())
    except OSError:
        return children
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            line = (entry / "stat").read_text()
        except OSError:
            continue
        rparen = line.rfind(")")
        if rparen == -1:
            continue
        fields = line[rparen + 2 :].split()
        if len(fields) > 1 and int(fields[1]) == ppid:
            children.append(int(entry.name))
    return children


def _signal_switch_tree(pid: int, sig: signal.Signals) -> None:
    """Holder plus its direct children (sudo, keeper) when SIGKILL skips Python handlers."""
    child_pids = _vm_fn("_child_pids", _child_pids)
    stack = [pid]
    seen: set[int] = set()
    while stack:
        target = stack.pop()
        if target in seen:
            continue
        seen.add(target)
        with contextlib.suppress(OSError, ProcessLookupError):
            _vm().os.kill(target, sig)
        stack.extend(child_pids(target))


def _preempt(fd: int, pid: int | None) -> bool:
    """Stop the switch holding the lock and take it. SIGTERM first (it
    unwinds through SwitchCancelled); SIGKILL if it doesn't let go — a
    holder stuck inside getaddrinfo only sees a Python signal handler once
    the C call returns. Never this process (a nested switch_lock) and never
    something that isn't ours."""
    vm = _vm()
    our_process = _vm_fn("_our_process", _our_process)
    signal_tree = _vm_fn("_signal_switch_tree", _signal_switch_tree)
    if pid is None or pid == vm.os.getpid() or not our_process(pid):
        return False
    for sig, wait in (
        (signal.SIGTERM, vm.PREEMPT_GRACE),
        (signal.SIGKILL, vm.PREEMPT_WAIT),
    ):
        if sig == signal.SIGTERM:
            getattr(vm, "terminate_registered_subprocesses", terminate_registered_subprocesses)()
        try:
            signal_tree(pid, sig)
        except PermissionError:
            return False
        if _wait_flock(fd, wait):
            return True
    return False


def _abort_checks() -> None:
    """SIGTERM every background check of the connection being left (CHECK_FLAGS)."""
    vm = _vm()
    me = vm.os.getpid()
    try:
        pids = [int(p.name) for p in vm.PROC.iterdir() if p.name.isdigit()]
    except OSError:
        return
    our_process = _vm_fn("_our_process", _our_process)
    for pid in pids:
        if pid != me and our_process(pid, CHECK_FLAGS):
            with contextlib.suppress(OSError):
                vm.os.kill(pid, signal.SIGTERM)
                logutil.log(f"switch: aborted check pid {pid}")


def _cancel_switch(signum, frame) -> None:
    vm = _vm()
    getattr(vm, "terminate_registered_subprocesses", terminate_registered_subprocesses)()
    raise SwitchCancelled


@contextlib.contextmanager
def switch_lock(action: str):
    """One switch at a time, whoever starts it (menu, panel, shortcut) —
    and the newest one wins.

    A connect can block for minutes (resolving endpoints through a dead
    tunnel), and refusing the next click ("Already switching") left the
    user stuck on a server without internet, unable to switch or even
    disconnect (2026-10-13). So a new switch supersedes the running one:
    it stops the holder (_preempt) and takes the lock; the holder unwinds
    through SwitchCancelled and stays silent. Before that, repeated clicks
    queued up and ran nine connects in the same second. flock, not a pid
    file: the kernel drops it when the holder dies, so a crash (or the
    SIGKILL) can't leave a stale lock. Taking it also stops the checks of
    the connection being left (_abort_checks)."""
    vm = _vm()
    vm_os = vm.os
    vm_time = vm.time
    lock = vm.SWITCH_LOCK
    lock.parent.mkdir(parents=True, exist_ok=True)
    fd = vm_os.open(lock, vm_os.O_RDWR | vm_os.O_CREAT, 0o600)
    try:
        seen, deadline = None, 0.0
        lock_holder = _vm_fn("_lock_holder", _lock_holder)
        preempt = _vm_fn("_preempt", _preempt)
        while not _try_flock(fd):
            pid, holder = lock_holder(fd)
            if preempt(fd, pid):
                logutil.log(f"switch superseded: {holder} -> {action}")
                break
            if pid == vm_os.getpid():
                raise SwitchBusy(holder)  # a nested switch_lock: waiting would wait on itself
            # mid-handover: another click killed the holder the file still names
            # and hasn't written its own pid yet, or won the lock off the holder
            # we were stopping — wait for it, then supersede it
            if pid != seen:
                seen, deadline = pid, vm_time.monotonic() + vm.HANDOVER_WAIT
            elif vm_time.monotonic() >= deadline:
                raise SwitchBusy(holder)
            vm_time.sleep(0.1)
        vm_os.ftruncate(fd, 0)
        vm_os.lseek(fd, 0, vm_os.SEEK_SET)
        vm_os.write(fd, f"{vm_os.getpid()}\n{action}".encode())
        _abort_checks()
        previous = signal.signal(signal.SIGTERM, _cancel_switch)
        try:
            yield
        finally:
            signal.signal(signal.SIGTERM, previous)
    finally:
        vm_os.close(fd)  # releases the flock


# held by whoever measures pings now: a Ping-all run or the queue's worker
# (_try_lock / ping_now). Once seven background sweeps ran at once, each
# spawned by a 3 s tick before the first could finish (2026-10-13).
PING_LOCK = Path.home() / ".cache/vpn-manager/ping.lock"


def _busy(e: SwitchBusy) -> ActionResult:
    logutil.log(f"switch refused, busy: {e}")
    return ActionResult(False, f"Already switching ({e}) — wait for it to finish")


def _cancelled(action: str) -> ActionResult:
    # the newer switch reports for itself; a second bubble would only confuse
    logutil.log(f"switch cancelled, superseded: {action}")
    return ActionResult(False, "")


def guarded_connect(provider, connection: VPNConnection) -> ActionResult:
    """_guarded_connect() under SWITCH_LOCK — the entry point for every connect."""
    action = f"connecting to {provider.name}: {connection.name}"
    # before the lock: a refused click must not supersede a switch or abort the app tunnel's checks
    if happ_provider.app_connected():  # the user's rule: the plugin or the app, never a fight
        return ActionResult(False, HAPP_APP_CONNECTED)
    try:
        with switch_lock(action):
            return _guarded_connect(provider, connection)
    except SwitchBusy as e:
        return _busy(e)
    except SwitchCancelled:
        return _cancelled(action)


KILLSWITCH_PROVIDERS = ("WireGuard", "AmneziaWG", "OpenVPN", "VLESS", "Shadowsocks")


def _killswitch_wanted(provider, enabled: bool) -> bool:
    """Whether this connect runs under the kill switch's rules (the rest —
    NetworkManager — suspends it: its endpoints aren't parsed)."""
    mode = killswitch.mode()
    if provider.name == "Happ":
        return enabled or mode in ("happ", "all")
    return provider.name in KILLSWITCH_PROVIDERS and mode == "all"


def _killswitch_targets(
    provider, connection: VPNConnection, cached_only: bool = False
) -> tuple[list[str], list[str]]:
    """(server IPs, tunnel interfaces) the rules must let through for this
    connect. cached_only: no DNS lookups, last known addresses only."""
    if provider.name != "Happ":
        return _killswitch_all_targets(cached_only=cached_only)
    # Under an enabled killswitch detect() finds nothing pre-connect (no
    # established xray sessions yet), so resolve the target server up front
    # and whitelist it explicitly — otherwise xray is blocked from reaching
    # it and the tunnel comes up dead. Cache-only: a menu click must never
    # block on a subscription fetch (the background --update-subs keeps the
    # caches fresh). Every balancer member, not just the first: xray may
    # dial any of them.
    endpoints = happmeta.server_endpoints(
        connection.name, allow_fetch=False, provider_id=connection.subscription_id
    )
    if not endpoints:
        return [], []
    # + subscription hosts: refreshing them goes through xray and is often
    # routed `direct` (Russian-hosted), which the killswitch blocks
    ips = killswitch.resolve_endpoint_ips(
        [(connection.name, host, port) for host, port in endpoints]
        + happmeta.subscription_targets(),
        cached_only=cached_only,
    )
    return ips, []


def _killswitch_apply(provider, ips: list[str], ifaces: list[str], dns: list[str]):
    if provider.name == "Happ":
        return killswitch.resume_for_happ(extra_ips=ips, dns=dns)
    return killswitch.enable(extra_ips=ips, ifaces=ifaces, dns=dns)


def _guarded_connect(provider, connection: VPNConnection) -> ActionResult:
    """Connect with killswitch interplay.

    Under the kill switch (_killswitch_wanted) the rules go in twice. Before
    the connect: the server's addresses plus port 53 to the system resolvers
    — the one hole, so endpoint hostnames resolve (ours, and wg-quick's
    Endpoint). After it: the same rules without that hole, so DNS leaves only
    through the tunnel, xray's mark or the LAN. The hole is closed in a
    `finally`: an early return or an exception must never leave it open.
    Other providers (NetworkManager) suspend an enabled kill switch.
    """
    cfg = config.load_config()
    enabled = killswitch.is_enabled()
    wanted = _killswitch_wanted(provider, enabled)
    ks_result = None
    ips: list[str] = []
    ifaces: list[str] = []
    hole_open = False
    if wanted:
        resolvers = killswitch.system_resolvers()
        if enabled and resolvers:
            # the current rules have no DNS hole: open it with the last known
            # addresses first, then resolve once with DNS working
            ips, ifaces = _killswitch_targets(provider, connection, cached_only=True)
            ks_result = _killswitch_apply(provider, ips, ifaces, resolvers)
            hole_open = ks_result is not None and ks_result.success
        fresh, ifaces = _killswitch_targets(provider, connection)
        if ks_result is None or not ks_result.success or set(fresh) != set(ips):
            ips = fresh
            ks_result = _killswitch_apply(provider, ips, ifaces, resolvers)
            hole_open = hole_open or bool(resolvers and ks_result and ks_result.success)
    elif enabled:
        ks_result = killswitch.suspend_for(provider.name)

    result = ActionResult(False, "")
    try:
        # one tunnel at a time: tear down anything else that is up before
        # connecting (two VPNs fight over the default route and traffic
        # splits unpredictably). Same-provider server switching is handled
        # inside the providers themselves (Happ/Keys stop their previous xray).
        others = [
            c
            for c in active_connections(providers=list(_provider_pool()))
            if not (c.provider == provider.name and c.name == connection.name)
        ]
        if others:
            down = _disconnect_all(for_switch=True)  # already under SWITCH_LOCK
            if not down.success:
                _sync_ipv6_guard()  # the teardown may have dropped everything anyway
                return down
        tuns_before = _tun_interfaces()
        result = provider.connect(connection)
        if hole_open and result.success and provider.name == "OpenVPN":
            # `openvpn --daemon` returns before it resolves `remote`: keep the
            # DNS hole until its tun device exists (or the wait runs out)
            _wait_for_new_tun(tuns_before, getattr(_vm(), "OPENVPN_TUN_WAIT", OPENVPN_TUN_WAIT))
    finally:
        if hole_open:
            closed = _close_dns_hole(provider, ips, ifaces, result.success, cfg)
            if closed is not None:
                ks_result = closed
    if ks_result and not ks_result.success:
        notify("Killswitch — warning", ks_result.message)
    if result.success:
        if cfg.dns_autotest:
            from app.checks import request_dns_autotest  # noqa: PLC0415 — break import cycle

            autotest = getattr(_vm(), "request_dns_autotest", None)
            if autotest is not None and autotest is not request_dns_autotest:
                autotest()
            else:
                request_dns_autotest()
        # don't re-probe: Happ reports success on happd's start ack, before
        # xray has created its TUN (and happd's process list may be the
        # cached pre-switch one) — a probe then sees nothing up and turned
        # IPv6 ON under a live tunnel. Success is proof enough.
        if cfg.ipv6_guard:
            _apply_ipv6_guard(ipv6guard.disable())
        else:
            _sync_ipv6_guard()
    else:
        _sync_ipv6_guard()
    return result


HAPP_APP_CONNECTED = (
    "The Happ app holds the connection — disconnect it first "
    "(in the Happ app, or the panel's switch)"
)
SYS_NET = Path("/sys/class/net")
OPENVPN_TUN_WAIT = 20.0  # s the connect-time DNS hole stays open for OpenVPN


def _tun_interfaces() -> set[str]:
    try:
        return {p.name for p in SYS_NET.iterdir() if p.name.startswith("tun")}
    except OSError:
        return set()


def _wait_for_new_tun(before: set[str], timeout: float) -> bool:
    vm_time = _vm().time
    tun_ifaces = _vm_fn("_tun_interfaces", _tun_interfaces)
    deadline = vm_time.monotonic() + timeout
    while not tun_ifaces() - before:
        if vm_time.monotonic() >= deadline:
            logutil.log(f"openvpn: no tun device after {timeout:g} s, closing the DNS hole anyway")
            return False
        vm_time.sleep(0.5)
    return True


def _close_dns_hole(provider, ips: list[str], ifaces: list[str], connected: bool, cfg):
    """After a connect: the strict rules, without the connect-time DNS hole.
    A failed connect with Lockdown off drops the rules instead — unless
    something still looks up, then the strict rules all the same."""
    if not connected and not cfg.killswitch_lockdown and _release_killswitch_if_unlocked(cfg):
        return None
    result = _killswitch_apply(provider, ips, ifaces, [])
    if result is not None and not result.success:
        result.message = f"could not close the connect-time DNS exception: {result.message}"
    return result


def guarded_disconnect(provider, connection: VPNConnection) -> ActionResult:
    """_guarded_disconnect() under SWITCH_LOCK."""
    action = f"disconnecting {provider.name}: {connection.name}"
    try:
        with switch_lock(action):
            return _guarded_disconnect(provider, connection)
    except SwitchBusy as e:
        return _busy(e)
    except SwitchCancelled:
        return _cancelled(action)


def _guarded_disconnect(provider, connection: VPNConnection) -> ActionResult:
    """provider.disconnect() plus keeping the IPv6 guard in sync — every
    menu disconnect action should go through this, not provider.disconnect
    directly, so IPv6 gets restored as soon as nothing is left active."""
    result = provider.disconnect(connection)
    _sync_ipv6_guard()
    _release_killswitch_if_unlocked()
    return result


def _release_killswitch_if_unlocked(cfg=None) -> bool:
    """Lockdown off: the rules exist only while a VPN is up. Lockdown on
    (the default) keeps blocking until the user turns the kill switch off;
    the preference itself stays, so the next connect sets the rules again.
    True when the rules were dropped."""
    remote = getattr(_vm(), "_release_killswitch_if_unlocked", None)
    if remote is not None and remote is not _release_killswitch_if_unlocked:
        try:
            return remote(cfg)
        except TypeError:
            return remote()
    if (cfg or config.load_config()).killswitch_lockdown:
        return False
    # happd may still be stopping, and --status ticks cache its process
    # list for 3 s: a stale "Happ is up" kept the rules after a disconnect
    happ_provider._invalidate_procs_cache()
    if active_connections(providers=list(_provider_pool())) or not killswitch.is_enabled():
        return False
    result = killswitch.disable()
    if not result.success:
        notify("Killswitch — warning", result.message)
    return result.success


def _sync_ipv6_guard() -> None:
    """IPv6 must be off while anything is tunneled (none of our providers
    route it, so it would otherwise leak straight past every tunnel) and
    back on once nothing is active."""
    remote = getattr(_vm(), "_sync_ipv6_guard", None)
    if remote is not None and remote is not _sync_ipv6_guard:
        remote()
        return
    guard = config.load_config().ipv6_guard  # ⚙ off: IPv6 stays (or comes back) on
    if guard and active_connections(providers=list(_provider_pool())):
        _apply_ipv6_guard(ipv6guard.disable())
    else:
        _apply_ipv6_guard(ipv6guard.enable())


def _enforce_ipv6_guard(active: list[VPNConnection], cfg) -> None:
    """--status: a tunnel that came up without the plugin (WireGuard autostart
    at boot, the Happ app, NM) gets IPv6 turned off too — the guard used to
    run only inside the plugin's own connect/disconnect. Logged, not notified:
    a failing sudo would otherwise raise a bubble every tick."""
    if active and cfg.ipv6_guard and not ipv6guard.is_disabled():
        guard = ipv6guard.disable()
        logutil.log(f"ipv6 guard: a tunnel is up, IPv6 off: {guard.success} {guard.message}")


def sync_ipv6_boot() -> ActionResult:
    """⚙ IPv6 guard at boot: a systemd drop-in turns IPv6 off before every
    autostarted WireGuard/AmneziaWG tunnel (they come up before login, long
    before the bar's first --status) — or no drop-ins with the guard off.
    Runs on an autostart change, a Settings save and `make install`."""
    state = "on" if config.load_config().ipv6_guard else "off"
    helper = getattr(_vm(), "run_helper", run_helper)
    code, out = helper("ipv6-boot", state)
    return ActionResult(code == 0, "" if code == 0 else f"IPv6 at boot: {out}")


def _apply_ipv6_guard(guard: ActionResult) -> None:
    if not guard.success:
        notify("IPv6 guard — warning", guard.message)


def disconnect_all() -> ActionResult:
    """_disconnect_all() under SWITCH_LOCK."""
    try:
        with switch_lock("disconnecting everything"):
            result = _disconnect_all()
            _release_killswitch_if_unlocked()  # not in _disconnect_all: a connect reuses it
            return result
    except SwitchBusy as e:
        return _busy(e)
    except SwitchCancelled:
        return _cancelled("disconnecting everything")


def _disconnect_all(for_switch: bool = False) -> ActionResult:
    """for_switch: a connect is tearing the old tunnel down — leave IPv6 off;
    the connect's own result decides (else IPv6 came back on between the old
    tunnel going down and the new one coming up)."""
    remote = getattr(_vm(), "_disconnect_all", None)
    if remote is not None and remote is not _disconnect_all:
        return remote(for_switch=for_switch)
    stopped, failed = [], []
    # act on everything, even providers hidden from the menu
    for provider in _provider_pool():
        for conn in provider.connections():
            if not conn.active:
                continue
            result = provider.disconnect(conn)
            if result.success:
                stopped.append(f"{provider.name}: {conn.name}")
            elif not any(c.active for c in provider.connections()):
                # reported failure, but nothing is up anymore — e.g. one
                # Happ disconnect stops every happd process at once
                stopped.append(f"{provider.name}: {conn.name}")
            else:
                failed.append(f"{provider.name}: {conn.name}")
    if not for_switch:
        _sync_ipv6_guard()
    if failed:
        return ActionResult(False, "Failed: " + ", ".join(failed))
    message = ", ".join(stopped) if stopped else "nothing was active"
    return ActionResult(True, f"Disconnected: {message}")


def _killswitch_all_targets(cached_only: bool = False) -> tuple[list[str], list[str]]:
    """'all' mode whitelist: IPv4 of every configured WireGuard/OpenVPN/
    Keys endpoint + the tunnel interface names to allow through.

    NetworkManager endpoints are not parsed (v1) — connecting one suspends
    the killswitch instead. One broken provider must not stop the others
    (pattern: _collect_ping_targets)."""
    remote = getattr(_vm(), "_killswitch_all_targets", None)
    if remote is not None and remote is not _killswitch_all_targets:
        return remote(cached_only=cached_only)
    targets: list[tuple[str, str, int]] = []
    ifaces: list[str] = []
    for provider in _provider_pool():
        if provider.name == "NetworkManager":
            continue  # endpoints not parsed (v1) — connecting one suspends the killswitch
        try:
            pt = provider.ping_targets()
        except Exception as e:  # noqa: BLE001 — one broken provider must not stop the rest
            logutil.log(f"killswitch targets: {provider.name} skipped: {e!r}")
            continue
        targets += pt
        if provider.name in ("WireGuard", "AmneziaWG"):
            # wg-quick/awg-quick name the interface after the profile, and
            # the kernel caps interface names at 15 chars (IFNAMSIZ=16 with
            # NUL) — longer names can never exist as wg/awg interfaces (such
            # profiles are unused or driven by NetworkManager, which has
            # no such limit) and nft rejects the whole ruleset for them.
            ifaces += [n for n, _, _ in pt if len(n) <= 15]
            for n, _, _ in pt:
                if len(n) > 15:
                    logutil.log(f"killswitch: iface name too long, skipped: {n}")
        elif provider.name == "OpenVPN":
            if pt:
                ifaces.append("tun*")  # OpenVPN tunnel interfaces
        elif isinstance(provider, KeysProvider) and pt:
            ifaces.append(provider.tunnel_iface)
    targets += happmeta.subscription_targets()  # refreshes must survive the killswitch
    return killswitch.resolve_endpoint_ips(targets, cached_only=cached_only), sorted(set(ifaces))


def _killswitch_toggle(on: bool) -> ActionResult:
    if not on:
        return killswitch.set_mode(False)
    if not config.load_config().killswitch_lockdown and not active_connections(
        providers=list(_provider_pool())
    ):
        return killswitch.set_mode(True, apply=False)  # nothing to protect yet
    ips, ifaces = _killswitch_all_targets()
    return killswitch.set_mode(True, extra_ips=ips, ifaces=ifaces)


KILLSWITCH_ICON = settings_tui.KILLSWITCH_ICON
