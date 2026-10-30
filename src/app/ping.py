"""On-demand ping measurement (--ping-now)."""

import os
import time
from pathlib import Path

import delayping
import killswitch
import logutil
from app.helpers import refresh_bar
from app.registry import _provider_pool
from app.switch import _try_flock
from providers.keys import KeysProvider


def _ping_lock() -> Path:
    import vpn_manager as vm  # noqa: PLC0415 — tests patch vpn_manager.PING_LOCK

    return vm.PING_LOCK


def _ping_scope_targets(
    scope: dict,
) -> tuple[list[tuple[str, dict]], list[tuple[str, str, int]]]:
    """(xray targets, direct targets) for a ping scope: {} = every server,
    {"group": <panel group id>}, {"server": [provider, name, subscription id]}.
    Happ/Keys go through xray (delayping); the rest keep the direct TCP connect."""
    group, server = scope.get("group"), scope.get("server")
    if server:
        pname, name, sub_id = [*server, "", "", ""][:3]
    elif group and str(group).startswith("happ:"):
        pname, name, sub_id = "Happ", None, str(group).split(":", 2)[1]
    else:
        pname, name, sub_id = group, None, None
    xray: list[tuple[str, dict]] = []
    direct: list[tuple[str, str, int]] = []
    for provider in _provider_pool():
        if pname and provider.name != pname:
            continue
        if provider.name == "Happ":
            xray += delayping.happ_targets(sub_id if (group or server) else None, name)
        elif isinstance(provider, KeysProvider):
            xray += delayping.key_targets(provider._kind, name)
        else:
            try:
                targets = provider.ping_targets()
            except Exception as e:  # noqa: BLE001 — one broken provider must not stop the rest
                logutil.log(f"ping targets: {provider.name} skipped: {e!r}")
                continue
            direct += [t for t in targets if name is None or t[0] == name]
    return xray, direct


def _try_lock(path: Path) -> int | None:
    """A held flock's fd (release: os.close), or None when another holds it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    if _try_flock(fd):
        return fd
    os.close(fd)
    return None


def _ping_worker_alive() -> bool:
    fd = _try_lock(_ping_lock())
    if fd is None:
        return True
    os.close(fd)
    return False


PING_REFRESH_EVERY = 2.0  # s between panel reloads while results come in (~230 ms each)


def _call_measure(scope: dict, kind: str) -> tuple[dict[str, dict], bool]:
    import vpn_manager as vm  # noqa: PLC0415 — tests patch vpn_manager._measure

    fn = getattr(vm, "_measure", _measure_body)
    return fn(scope, kind)


def _measure_body(scope: dict, kind: str) -> tuple[dict[str, dict], bool]:
    xray, direct = _ping_scope_targets(scope)
    direct_allowed = not direct or not killswitch.is_enabled()
    last = time.monotonic()

    def on_progress(done: int, total: int) -> None:
        # an open panel shows each result as it arrives — reloading its list
        # at most every PING_REFRESH_EVERY (the caller refreshes at the end)
        nonlocal last
        if done < total and time.monotonic() - last >= PING_REFRESH_EVERY:
            last = time.monotonic()
            refresh_bar()

    results = delayping.run(xray, direct, direct_allowed, kind=kind, on_progress=on_progress)
    return results, direct_allowed


_measure = _measure_body  # vpn_manager re-export; tests patch the module attribute


def ping_now(scope: dict | None = None) -> tuple[str, str] | None:
    """--ping-now: the only way pings are measured (no background sweep —
    the user's call). Happ/Keys go through xray under happd (delayping),
    which the kill switch lets through; WireGuard/OpenVPN keep the direct
    TCP connect, which it drops — skipped while it is on.

    No scope: the Ping button for everything — refused while anything is
    measured. A row's or a group's scope (click on its ping, or `p`) goes
    into a queue, never twice, and is refused while Ping-all runs; the
    first such process becomes the worker and drains the queue one scope
    at a time (so their cache writes never race). Returns the notification,
    None for a quiet queued ping (the panel shows "…" on its rows)."""
    if not scope:
        with delayping.queue_locked():
            fd = _try_lock(_ping_lock())
            if fd is None:
                progress = delayping.read_progress() or {}
                if progress.get("kind") == delayping.ALL:
                    return "Ping", "Already measuring — the list updates when it's done"
                return "Ping", "Wait for the queued pings to finish"
            delayping.write_queue([])  # lock was free: whatever is left is stale
            delayping.write_progress(0, 0, delayping.ALL)  # queued pings see it at once
        try:
            refresh_bar()  # the bar shows the progress ({activity}), rows "…"
            results, direct_allowed = _call_measure({}, delayping.ALL)
        finally:
            os.close(fd)
        refresh_bar()  # an open panel reloads its list
        answered = sum(1 for r in results.values() if r.get("ms") is not None)
        message = f"{answered}/{len(results)} servers answered"
        if not direct_allowed:
            message += " — WireGuard/OpenVPN skipped: the kill switch drops direct pings"
        return "Ping", message

    with delayping.queue_locked():
        progress = delayping.read_progress() or {}
        if progress.get("kind") == delayping.ALL:
            return "Ping", "Ping all is running — this one is measured with it"
        queue = delayping.read_queue()
        if scope not in queue:
            delayping.write_queue([*queue, scope])
        fd = _try_lock(_ping_lock())
    refresh_bar()  # its rows show "…" while queued
    if fd is None:
        return None  # the running worker picks it up
    try:
        while True:
            with delayping.queue_locked():
                queue = delayping.read_queue()
                if not queue:
                    break
                current = queue[0]
            try:
                _call_measure(current, delayping.QUEUED)
            except Exception as e:  # noqa: BLE001 — one bad scope must not stall the queue
                logutil.log(f"ping {current}: {e!r}")
            with delayping.queue_locked():
                delayping.write_queue([s for s in delayping.read_queue() if s != current])
            refresh_bar()  # its result shows
    finally:
        os.close(fd)  # under no queue lock: a request added just now finds it free
    # a scope queued between the empty check and the release would wait for
    # the next click — take it now
    if delayping.read_queue():
        return ping_now(delayping.read_queue()[0])
    return None


def _ping_scope_from_args(argv: list[str]) -> dict | None:
    """--ping-now [group ID | server PROVIDER NAME [SUBSCRIPTION_ID]]."""
    if not argv:
        return {}
    if argv[0] == "group" and len(argv) == 2:
        return {"group": argv[1]}
    if argv[0] == "server" and len(argv) in (3, 4):
        return {"server": [argv[1], argv[2], argv[3] if len(argv) == 4 else ""]}
    return None
