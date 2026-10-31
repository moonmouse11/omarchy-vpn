"""Long-lived INCY xray process (no happd)."""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import fsutil
import logutil
from incy.config import TUN_IFACE, resolve_config
from incy.xray import config_error
from incy.xray_run import KEEPER_CFG, popen_xray

KEEPER_STATE = Path.home() / ".local/state/vpn-manager/incy-keeper.json"
XRAY_START_TIMEOUT = 25.0


def _pub():
    import providers.incy as m  # noqa: PLC0415 — tests patch providers.incy

    return m


def _read_state() -> dict | None:
    try:
        data = json.loads(KEEPER_STATE.read_text())
    except OSError, json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _write_state(state: dict) -> None:
    fsutil.write_json_atomic(_pub().KEEPER_STATE, state)


def _write_own_state(state: dict) -> None:
    current = _read_state()
    if current is not None and current.get("pid") not in (None, os.getpid()):
        return
    _write_state(state)


def _iface_up() -> bool:
    return Path(f"/sys/class/net/{TUN_IFACE}").exists()


def _wait_iface(deadline: float) -> bool:
    while time.time() < deadline:
        if _iface_up():
            return True
        time.sleep(0.2)
    return False


def run_keeper(server_name: str | None = None, provider_id: str | None = None) -> None:
    logutil.log(f"incy keeper: starting ({server_name or '?'})")
    state: dict = {"status": "connecting", "pid": os.getpid()}
    _write_state(state)
    proc: subprocess.Popen[bytes] | None = None
    try:
        name = server_name or ""
        cfg = resolve_config(name, provider_id=provider_id, allow_fetch=False)
        if cfg is None and provider_id:
            cfg = resolve_config(name, provider_id=provider_id, allow_fetch=True)
        if cfg is None:
            state.update(
                status="error",
                message="no config for this server — refresh subscription cache",
            )
            _write_own_state(state)
            return
        if reason := config_error(cfg):
            state.update(status="error", message=f"xray rejected the config: {reason}")
            _write_own_state(state)
            return

        try:
            proc = popen_xray(cfg, KEEPER_CFG)
        except OSError as e:
            state.update(status="error", message=str(e))
            _write_own_state(state)
            return
        state["xray_pid"] = proc.pid
        deadline = time.time() + XRAY_START_TIMEOUT
        if not _wait_iface(deadline):
            state.update(
                status="error",
                message=f"TUN {TUN_IFACE} did not come up — re-run make install (incy-run helper)",
            )
            _write_own_state(state)
            return
        state.update(
            status="connected",
            server=cfg.get("remarks") or server_name,
            provider_id=provider_id,
        )
        _write_own_state(state)
        logutil.log(f"incy keeper: connected ({state.get('server')})")

        while True:
            if proc.poll() is not None:
                break
            current = _read_state()
            if current is None or current.get("pid") != os.getpid():
                break
            time.sleep(0.5)
    except OSError as e:
        logutil.log(f"incy keeper: {e}")
        state.update(status="error", message=str(e))
        _write_own_state(state)
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        state.update(status="exited")
        _write_own_state(state)
        logutil.log("incy keeper: exited")
