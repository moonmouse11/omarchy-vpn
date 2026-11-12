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
import providers.incy as incy_provider
from app.helpers import notify
from app.registry import _provider_pool, active_connections
from providers.base import (
    ActionResult,
    PingTarget,
    VPNConnection,
    run_helper,
    terminate_registered_subprocesses,
)
from providers.keys import KeysProvider
from vpn_dns import snapshot

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


class SwitchCancelled(BaseException):  # NOSONAR — must not inherit Exception; see docstring
    """This switch was superseded by a newer one (SIGTERM from its switch_lock).
    BaseException, like KeyboardInterrupt: a provider's `except Exception`
    must not swallow it and carry on connecting."""


class CheckCancelled(BaseException):  # NOSONAR — see SwitchCancelled
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
    if incy_provider.app_connected():
        return ActionResult(False, INCY_APP_CONNECTED)
    try:
        with switch_lock(action):
            return _guarded_connect(provider, connection)
    except SwitchBusy as e:
        return _busy(e)
    except SwitchCancelled:
        return _cancelled(action)


KILLSWITCH_PROVIDERS = ("WireGuard", "AmneziaWG", "OpenVPN", "VLESS", "Shadowsocks", "INCY")


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
    if provider.name == "INCY":
        from incy.config import TUN_IFACE  # noqa: PLC0415
        from incy.config import server_endpoints as incy_endpoints  # noqa: PLC0415
        from incy.subscriptions import subscription_targets  # noqa: PLC0415

        endpoints = incy_endpoints(
            connection.name, provider_id=connection.subscription_id, allow_fetch=False
        )
        if not endpoints:
            return [], []
        ips = killswitch.resolve_endpoint_ips(
            [(connection.name, host, port) for host, port in endpoints] + subscription_targets(),
            cached_only=cached_only,
        )
        return ips, [TUN_IFACE]
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
    # No detect()/saved IP merge: the whitelist must be the selected snapshot.
    return killswitch.enable(extra_ips=ips, ifaces=ifaces, dns=dns, fresh=True)


class _ConnectFirewall:
    """Keep the armed snapshot and bootstrap permission available to finally cleanup."""

    def __init__(self, provider):
        self.provider = provider
        self.enabled = killswitch.is_enabled()
        self.wanted = _killswitch_wanted(provider, self.enabled)
        self.ips: list[str] = []
        self.ifaces: list[str] = []
        self.resolvers: list[str] = []
        self.result: ActionResult | None = None
        self.bootstrap_open = False

    def _apply(self) -> None:
        self.result = _killswitch_apply(self.provider, self.ips, self.ifaces, self.resolvers)
        self.bootstrap_open = self.bootstrap_open or bool(
            self.resolvers and self.result and self.result.success
        )

    def arm(self, connection: VPNConnection, numeric: bool) -> ActionResult | None:
        if not self.wanted:
            if self.enabled:
                self.result = killswitch.suspend_for(self.provider.name)
            return self.result
        self.resolvers = killswitch.system_resolvers()
        if self.resolvers:
            # Arm before lookups; only the dedicated marked sockets may use bootstrap DNS.
            self.ips, self.ifaces = _killswitch_targets(self.provider, connection, cached_only=True)
            self._apply()
            if not self.bootstrap_open:
                return ActionResult(
                    False, self.result.message if self.result else "Could not arm killswitch"
                )
        fresh, self.ifaces = _killswitch_targets(self.provider, connection, cached_only=numeric)
        if self.result is None or not self.result.success or set(fresh) != set(self.ips):
            self.ips = fresh
            self._apply()
        return self.result

    def refresh_dns(self) -> ActionResult | None:
        if not self.wanted:
            return None
        resolvers = killswitch.system_resolvers()
        if set(resolvers) == set(self.resolvers):
            return None
        self.resolvers = resolvers
        self._apply()
        return self.result

    def select_numeric(self, connection: VPNConnection, kind: str) -> bool:
        self.ips = connection.endpoint_ipv4 or []
        self.ifaces = ["tun*"] if kind == "ovpn" else [connection.interface or connection.name]
        if not self.wanted:
            return True
        self._apply()
        return self.result is not None and self.result.success

    def close(self, connected: bool, cfg) -> ActionResult | None:
        if self.bootstrap_open:
            closed = _close_dns_hole(self.provider, self.ips, self.ifaces, connected, cfg)
            if closed is not None:
                self.result = closed
        return self.result


def _disconnect_other_connections(provider, connection: VPNConnection) -> ActionResult | None:
    # Same-provider server replacement belongs to the provider; other tunnels fight over routing.
    others = [
        c
        for c in active_connections(providers=list(_provider_pool()))
        if not (c.provider == provider.name and c.name == connection.name)
    ]
    if not others:
        return None
    down = _disconnect_all(for_switch=True)  # already under SWITCH_LOCK
    if not down.success:
        _sync_ipv6_guard()  # the teardown may have dropped everything anyway
    return down


def _prepare_connection(
    provider, connection: VPNConnection, firewall: _ConnectFirewall
) -> ActionResult | None:
    kind = getattr(provider, "helper_kind", "")
    if kind in ("wg", "awg", "ovpn"):
        try:
            addresses, selected_ips = snapshot.resolve_profile(kind, connection.name)
        except (OSError, ValueError) as error:
            _sync_ipv6_guard()
            return ActionResult(False, f"Endpoint bootstrap failed: {error}")
        connection.endpoint_addresses = addresses
        connection.endpoint_ipv4 = selected_ips
        if not firewall.select_numeric(connection, kind):
            _sync_ipv6_guard()
            return ActionResult(False, "Could not install endpoint firewall rules")
    return None


def _after_connect(result: ActionResult, cfg) -> None:
    if result.success and cfg.dns_autotest:
        from app.checks import request_dns_autotest  # noqa: PLC0415 — break import cycle

        _vm_fn("request_dns_autotest", request_dns_autotest)()
    # Happ acknowledges before its TUN exists: success, not a stale active probe, earns the guard.
    if result.success and cfg.ipv6_guard:
        _apply_ipv6_guard(ipv6guard.disable())
    else:
        _sync_ipv6_guard()


def _guarded_connect(provider, connection: VPNConnection) -> ActionResult:
    """Arm, tear down, bootstrap and start; always retire the bootstrap permission.

    Ordinary apps/shared-resolved never get a connect-time DNS exception.
    Native profiles use the same numeric snapshot as the firewall.
    NetworkManager still suspends an enabled kill switch.
    """
    cfg = config.load_config()
    firewall = _ConnectFirewall(provider)
    connection.endpoint_addresses = None
    connection.endpoint_ipv4 = None
    result = ActionResult(False, "")
    try:
        numeric = getattr(provider, "helper_kind", "") in ("wg", "awg", "ovpn")
        armed = firewall.arm(connection, numeric)
        if armed is not None and not armed.success:
            return ActionResult(False, armed.message)
        down = _disconnect_other_connections(provider, connection)
        if down is not None and not down.success:
            return down
        refreshed = firewall.refresh_dns()
        if refreshed is not None and not refreshed.success:
            _sync_ipv6_guard()
            return ActionResult(False, refreshed.message)
        prepared = _prepare_connection(provider, connection, firewall)
        if prepared is not None:
            result = prepared
            return result
        tuns_before = _tun_interfaces()
        try:
            result = provider.connect(connection)
        except SwitchCancelled:
            # The newer user action owns the machine now. Cancel any vendor daemon
            # intent accepted before this process was superseded, then stay silent.
            with contextlib.suppress(Exception):
                provider.disconnect(connection)
            raise
        if firewall.bootstrap_open and result.success and provider.name == "OpenVPN":
            # Numeric remotes do not need DNS here; preserve the existing TUN readiness timing.
            _wait_for_new_tun(tuns_before, getattr(_vm(), "OPENVPN_TUN_WAIT", OPENVPN_TUN_WAIT))
    finally:
        connection.endpoint_addresses = None
        connection.endpoint_ipv4 = None
        ks_result = firewall.close(result.success, cfg)
    if ks_result and not ks_result.success:
        notify("Killswitch — warning", ks_result.message)
    _after_connect(result, cfg)
    return result


HAPP_APP_CONNECTED = (
    "The Happ app holds the connection — disconnect it first "
    "(in the Happ app, or the panel's switch)"
)
INCY_APP_CONNECTED = (
    "The INCY app holds the connection — disconnect it in INCY first (same one-tunnel rule as Happ)"
)
SYS_NET = Path("/sys/class/net")
OPENVPN_TUN_WAIT = 20.0  # s to wait for OpenVPN's daemon-created TUN


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
            logutil.log(f"openvpn: no tun device after {timeout:g} s, ending bootstrap allowance")
            return False
        vm_time.sleep(0.5)
    return True


def _close_dns_hole(provider, ips: list[str], ifaces: list[str], connected: bool, cfg):
    """After a connect: strict rules without the marked bootstrap allowance.
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


def _disconnect_connection(provider, connection: VPNConnection) -> bool:
    result = provider.disconnect(connection)
    # Windscribe already polls: an unavailable status is not proof of teardown.
    if result.success or provider.name == "Windscribe":
        return result.success
    # A failed reply may still mean stopped, e.g. one Happ stop ends every happd process.
    return not active_connections(providers=[provider])


def _disconnect_all(for_switch: bool = False) -> ActionResult:
    """for_switch: a connect is tearing the old tunnel down — leave IPv6 off;
    the connect's own result decides (else IPv6 came back on between the old
    tunnel going down and the new one coming up)."""
    remote = getattr(_vm(), "_disconnect_all", None)
    if remote is not None and remote is not _disconnect_all:
        return remote(for_switch=for_switch)
    stopped, failed = [], []
    lockdown_warnings: list[str] = []
    # act on everything, even providers hidden from the menu
    for provider in _provider_pool():
        for conn in active_connections(providers=[provider]):
            if _disconnect_connection(provider, conn):
                stopped.append(f"{provider.name}: {conn.name}")
                if for_switch:
                    hint_fn = getattr(provider, "lockdown_hint", None)
                    if hint_fn is not None:
                        try:
                            hint = hint_fn(conn)
                        except Exception:  # noqa: BLE001 — a broken provider
                            hint = None  # must not break the switch
                        if hint:
                            lockdown_warnings.append(hint)
            else:
                failed.append(f"{provider.name}: {conn.name}")
    for warning in lockdown_warnings:
        notify("Vendor lockdown — warning", warning)
    if not for_switch:
        _sync_ipv6_guard()
    if failed:
        return ActionResult(False, "Failed: " + ", ".join(failed))
    message = ", ".join(stopped) if stopped else "nothing was active"
    return ActionResult(True, f"Disconnected: {message}")


def _provider_tunnel_ifaces(provider, targets: list[PingTarget]) -> list[str]:
    if provider.name in ("WireGuard", "AmneziaWG"):
        # IFNAMSIZ includes NUL; longer profile names cannot be interfaces and nft rejects them.
        names = [target[0] for target in targets]
        for name in names:
            if len(name) > 15:
                logutil.log(f"killswitch: iface name too long, skipped: {name}")
        return [name for name in names if len(name) <= 15]
    if not targets:
        return []
    if provider.name == "OpenVPN":
        return ["tun*"]
    if isinstance(provider, KeysProvider):
        return [provider.tunnel_iface]
    return []


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
        targets += [(t[0], t[1], t[2]) for t in pt]
        ifaces += _provider_tunnel_ifaces(provider, pt)
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
