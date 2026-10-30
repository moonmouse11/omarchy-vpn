"""Server delay measured through xray — the panel's Ping button (--ping-now).

Like the Happ app: every Happ/Keys server gets its own short-lived xray with a
local HTTP proxy inbound, and one HTTPS request to Happ's ping test URL goes
through it; the time to the answer is the delay shown. The xray runs under
happd (root, its cgroup — no sudo rule of our own), so its outbounds carry
KILLSWITCH_MARK and pass the kill switch. Each one is bound to the uplink
(sockopt.interface): xray without a TUN inbound would otherwise follow the
default route into the running tunnel and time the path through the current
server. happd reaps a process when the session that started it closes, so a
crashed or cancelled sweep leaves no xray behind.

WireGuard/OpenVPN can't go through xray: they keep the direct TCP connect
(happmeta.measure_ping) — dropped by the kill switch, so skipped under it.
"""

import concurrent
import contextlib
import copy
import fcntl
import json
import os
import socket
import subprocess
import threading
import time
import urllib
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import fsutil
import happmeta
import lazyimports  # noqa: F401 — registers urllib.request/concurrent.futures lazily
from providers import happ, keys
from providers.base import PingTarget

if TYPE_CHECKING:  # loaded lazily at run time, see lazyimports.py
    import concurrent.futures
    import urllib.error
    import urllib.request

PROGRESS = Path.home() / ".cache/vpn-manager/ping-progress.json"
QUEUE = Path.home() / ".cache/vpn-manager/ping-queue.json"
QUEUE_LOCK = Path.home() / ".cache/vpn-manager/ping-queue.lock"
ALL, QUEUED = "all", "queued"  # progress "kind": the Ping-all button, or the queue
PROCESS_PREFIX = happ.PING_PROCESS_PREFIX
INBOUND_TAG = "ping-in"
DEFAULT_TEST_URL = "https://www.gstatic.com/generate_204"  # Happ's built-in default
DEFAULT_CONCURRENCY = 8
MAX_CONCURRENCY = 32
REQUEST_TIMEOUT = 5.0  # s for the request through a server
LISTEN_TIMEOUT = 3.0  # s for a started xray to open its inbound
SKIPPED = "skipped"  # cache marker: not measured (direct ping under the kill switch)


# ── Happ's own ping settings ─────────────────────────────────────────────────


def _happ_setting(key: str) -> str | None:
    """Preferences/PingSettings/<key> from the Happ app's Happ.conf (QSettings
    INI: `PingSettings\\pingTestUrl=...` under [Preferences]), or None."""
    try:
        lines = happ.GUI_CONFIG.read_text(errors="replace").splitlines()
    except OSError:
        return None
    section = ""
    for raw in lines:
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        name, sep, value = line.partition("=")
        if section == "Preferences" and sep and name.strip() == f"PingSettings\\{key}":
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            return value or None
    return None


def test_url() -> str:
    url = _happ_setting("pingTestUrl")
    return url if url and url.startswith(("http://", "https://")) else DEFAULT_TEST_URL


def concurrency() -> int:
    try:
        n = int(_happ_setting("pingConcurrency") or DEFAULT_CONCURRENCY)
    except ValueError:
        n = DEFAULT_CONCURRENCY
    return max(1, min(n, MAX_CONCURRENCY))


# ── The probe config ─────────────────────────────────────────────────────────


def _probe_target(cfg: dict) -> dict:
    """Where the subscription sends app traffic: the dns-in rule's target
    (build_runtime_config pins it to the subscription's catch-all, balancer
    included), else _tunnel_target() — never a split-tunnel `direct`."""
    rules = cfg.get("routing", {}).get("rules") or []
    for rule in rules:
        if rule.get("inboundTag") == ["dns-in"]:
            return {k: rule[k] for k in ("balancerTag", "outboundTag") if k in rule}
    return happmeta._tunnel_target(rules, cfg.get("outbounds") or [])


def probe_config(runtime_cfg: dict, port: int, uplink: str | None) -> dict:
    """A tunnel config (build_runtime_config's shape) turned into a probe:
    no TUN and no shared 10808/10809 inbounds (the keeper's xray holds
    those), one HTTP inbound on 127.0.0.1:port routed straight to the
    server, and every marked outbound bound to the uplink."""
    cfg = copy.deepcopy(runtime_cfg)
    cfg["inbounds"] = [
        {"listen": "127.0.0.1", "port": port, "protocol": "http", "tag": INBOUND_TAG}
    ]
    routing = cfg.setdefault("routing", {})
    target = _probe_target(cfg)
    routing["rules"] = [
        {"inboundTag": [INBOUND_TAG], **target},
        {"inboundTag": [happmeta.DNS_BOOTSTRAP_TAG], "outboundTag": "dns-direct"},
    ]
    for outbound in cfg.get("outbounds") or []:
        sockopt = (outbound.get("streamSettings") or {}).get("sockopt") or {}
        if uplink and sockopt.get("mark") == happmeta.KILLSWITCH_MARK:
            sockopt["interface"] = uplink
    cfg["log"] = {"loglevel": "warning"}
    return cfg


def happ_targets(
    subscription_id: str | None = None, name: str | None = None
) -> list[tuple[str, dict]]:
    """(ping cache key, tunnel config) for the Happ servers — all, one
    subscription's, or one server. Keyed by (subscription, name):
    happmeta.ping_key()."""
    targets: dict[str, dict] = {}
    for server in happmeta.all_servers(allow_fetch=False):
        sub_id = server.get("provider_id") or ""
        if subscription_id is not None and sub_id != subscription_id:
            continue
        if name is not None and server["name"] != name:
            continue
        cfg = server["config"]
        if sub_id:
            cfg = happmeta.build_runtime_config(cfg, tunnel_dns=True)
        targets.setdefault(happmeta.ping_key(server["name"], sub_id), cfg)
    return list(targets.items())


def incy_targets(
    subscription_id: str | None = None, name: str | None = None
) -> list[tuple[str, dict]]:
    """(ping cache key, tunnel config) for INCY servers — xray runs locally."""
    from incy.config import build_incy_runtime_config  # noqa: PLC0415 — lazy
    from incy.subscriptions import all_catalog_entries  # noqa: PLC0415 — lazy

    targets: dict[str, dict] = {}
    for entry in all_catalog_entries(allow_fetch=False):
        sub_id = entry.get("provider_id") or ""
        if subscription_id is not None and sub_id != subscription_id:
            continue
        if name is not None and entry["name"] != name:
            continue
        cfg = build_incy_runtime_config(entry["config"], tunnel_dns=True)
        targets.setdefault(happmeta.ping_key(entry["name"], sub_id), cfg)
    return list(targets.items())


def key_targets(kind: str | None = None, name: str | None = None) -> list[tuple[str, dict]]:
    """(name, tunnel config) for the imported keys — all, one kind's, or one."""
    targets: dict[str, dict] = {}
    for key in keys._load_servers():
        if (kind is not None and key.get("kind") != kind) or (
            name is not None and key.get("name") != name
        ):
            continue
        with contextlib.suppress(KeyError, TypeError, ValueError):
            targets.setdefault(key["name"], keys._build_xray_config(key))
    return list(targets.items())


def xray_targets() -> list[tuple[str, dict]]:
    """Every Happ server and every key."""
    return happ_targets() + key_targets()


# ── One probe ────────────────────────────────────────────────────────────────


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_listening(port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.3)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.05)
    return False


def _request_ms(port: int, url: str) -> float | None:
    """Time to the answer of one request through the local proxy; any HTTP
    status counts (a 204 or a redirect still crossed the server)."""
    proxy = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    )
    start = time.perf_counter()
    try:
        with opener.open(url, timeout=REQUEST_TIMEOUT) as resp:
            resp.read(0)
    except urllib.error.HTTPError:
        pass  # an answer all the same
    except OSError, ValueError:
        return None
    return round((time.perf_counter() - start) * 1000, 1)


def _start(sock: socket.socket, process_id: str, cfg: dict) -> bool:
    """happd's start frame (as the keeper sends it); True once acknowledged."""
    request_id = f"ping-{time.time_ns()}"
    params: dict = {
        "action": "start",
        "arguments": [],
        "executable": str(happ.XRAY_BIN),
        "process-id": process_id,
        "request-id": request_id,
        "stdin-data": json.dumps(cfg),
    }
    if asset_dir := happ._routing_asset_dir():
        params["environment"] = {"XRAY_LOCATION_ASSET": str(asset_dir)}
    happ._send_frame(sock, params)
    deadline = time.monotonic() + happ.XRAY_TIMEOUT
    while time.monotonic() < deadline:
        try:
            frame = happ._recv_frame(sock)
        except TimeoutError:
            continue
        if frame and frame.get("request-id") == request_id:
            return frame.get("status") in ("started", "success")
    return False


def incy_probe(runtime_cfg: dict, url: str, uplink: str | None) -> float | None:
    """Delay through one INCY server via a short-lived local xray (no happd)."""
    from incy.xray_run import PROBE_CFG, popen_xray  # noqa: PLC0415

    port = _free_port()
    cfg = probe_config(runtime_cfg, port, uplink)
    proc: subprocess.Popen[bytes] | None = None
    try:
        proc = popen_xray(cfg, PROBE_CFG)
        if not _wait_listening(port, LISTEN_TIMEOUT):
            return None
        return _request_ms(port, url)
    except OSError:
        return None
    finally:
        if proc is not None and proc.poll() is None:
            with contextlib.suppress(OSError, ProcessLookupError):
                proc.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=2)


def probe(process_id: str, runtime_cfg: dict, url: str, uplink: str | None) -> float | None:
    """Delay through one server, None when it doesn't answer."""
    port = _free_port()
    sock = happ._open_session()
    try:
        if not _start(sock, process_id, probe_config(runtime_cfg, port, uplink)):
            return None
        if not _wait_listening(port, LISTEN_TIMEOUT):
            return None
        return _request_ms(port, url)
    finally:
        with contextlib.suppress(OSError):
            happ._daemon_request("stop", **{"process-id": process_id})
        sock.close()  # happd reaps what this session started, whatever happened above


# ── The sweep ────────────────────────────────────────────────────────────────


def read_progress() -> dict | None:
    """{done, total} of a sweep that is running now, else None (a crashed
    sweep's file names a dead pid)."""
    try:
        data = json.loads(PROGRESS.read_text())
        os.kill(int(data["pid"]), 0)
    except OSError, ValueError, KeyError, TypeError:
        return None
    return data


def write_progress(done: int, total: int, kind: str = ALL, started: float | None = None) -> None:
    """started: when this run began — a row measured after it shows its
    result while the rest of the run is still going."""
    with contextlib.suppress(OSError):
        fsutil.write_json_atomic(
            PROGRESS,
            {
                "pid": os.getpid(),
                "done": done,
                "total": total,
                "kind": kind,
                "started": time.time() if started is None else started,
            },
        )


# ── The queue of single pings (a row's or a group's) ─────────────────────────


@contextlib.contextmanager
def queue_locked() -> Iterator[None]:
    """Every read-modify-write of the queue — and the moves that must be
    atomic with it (becoming the worker, letting go of it) — under one lock."""
    QUEUE_LOCK.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(QUEUE_LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def read_queue() -> list[dict]:
    try:
        data = json.loads(QUEUE.read_text())
    except OSError, ValueError:
        return []
    return [s for s in data if isinstance(s, dict)] if isinstance(data, list) else []


def write_queue(scopes: list[dict]) -> None:
    with contextlib.suppress(OSError):
        if scopes:
            fsutil.write_json_atomic(QUEUE, scopes, ensure_ascii=False)
        else:
            QUEUE.unlink(missing_ok=True)


def _merge_into_cache(results: dict[str, dict]) -> None:
    pings = happmeta._read_pings()
    pings.update(results)
    pings["updated_at"] = time.time()
    with contextlib.suppress(OSError):
        fsutil.write_json_atomic(happmeta.PING_CACHE, pings, ensure_ascii=False)


def run(
    xray: list[tuple[str, dict]],
    direct: list[PingTarget],
    direct_allowed: bool,
    kind: str = ALL,
    on_progress: Callable[[int, int], None] | None = None,
    *,
    xray_incy: list[tuple[str, dict]] | None = None,
) -> dict[str, dict]:
    """Measure the xray servers (in parallel, Happ's concurrency) and the
    direct targets (WireGuard/OpenVPN; marked skipped when not allowed) and
    return the results. Each one goes into the ping cache as it arrives, so
    the panel shows it while the rest are still measured (and a cancelled
    run keeps what it got). kind (ALL or QUEUED) goes into the progress
    file: a queued ping is refused while an ALL run is on. on_progress runs
    outside the lock (it may refresh the panel)."""
    incy = xray_incy or []
    total = len(xray) + len(incy) + len(direct)
    started = time.time()
    url, uplink = test_url(), happmeta.uplink_interface()
    results: dict[str, dict] = {}
    lock = threading.Lock()
    slots = list(range(concurrency()))
    done = 0

    def finished(name: str, entry: dict) -> None:
        nonlocal done
        with lock:  # one writer at a time: threads would overwrite each other
            results[name] = entry
            done += 1
            _merge_into_cache({name: entry})
            write_progress(done, total, kind, started)
            count = done
        if on_progress:
            on_progress(count, total)

    def one_happ(name: str, cfg: dict) -> None:
        with lock:
            slot = slots.pop()
        try:
            ms = probe(f"{PROCESS_PREFIX}{slot}", cfg, url, uplink)
        except OSError:
            ms = None
        finally:
            with lock:
                slots.append(slot)
        finished(name, {"ms": ms, "at": time.time()})

    def one_incy(name: str, cfg: dict) -> None:
        try:
            ms = incy_probe(cfg, url, uplink)
        except OSError:
            ms = None
        finished(name, {"ms": ms, "at": time.time()})

    write_progress(0, total, kind, started)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(slots)) as pool:
            futures = [pool.submit(one_happ, name, cfg) for name, cfg in xray]
            futures += [pool.submit(one_incy, name, cfg) for name, cfg in incy]
            for future in futures:
                future.result()
        for item in direct:
            name, host, port = item[0], item[1], item[2]
            icmp_only = len(item) > 3 and bool(item[3])
            if not direct_allowed:
                finished(name, {"ms": None, "at": time.time(), SKIPPED: True})
                continue
            try:
                ms = happmeta.measure_ping(host, port, icmp_only=icmp_only)
            except OSError, OverflowError, ValueError, TypeError:
                ms = None
            finished(name, {"ms": ms, "at": time.time()})
    finally:
        with contextlib.suppress(OSError):
            PROGRESS.unlink(missing_ok=True)
    return results
