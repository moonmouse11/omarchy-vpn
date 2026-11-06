"""INCY (https://incy.cc) — xray subscriptions without happd."""

from __future__ import annotations

import contextlib
import json
import os
import signal
import sqlite3
import sys
import time
from pathlib import Path

from incy.config import TUN_IFACE
from providers.common.types import ActionResult, PingTarget, VPNConnection, VPNProvider

INCY_CONFIG = Path.home() / ".config/incy"
INCY_SOCK = Path.home() / ".cache/incy/incy.sock"
IFACE_PREFIX = "incy-"
_INCY_LINK = Path(f"/sys/class/net/{TUN_IFACE}")
_GUI_LINK = Path("/sys/class/net/tun_incy")


def _incy_link_up() -> bool:
    try:
        return _INCY_LINK.is_dir() or _GUI_LINK.is_dir()
    except OSError:
        return False


def _subscription_name(sub_id: str | None) -> str | None:
    if not sub_id:
        return None
    db = _pub().INCY_DB
    if not db.is_file():
        return None
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.0)
    except sqlite3.Error:
        return None
    try:
        row = conn.execute(
            """
            SELECT COALESCE(NULLIF(profileName, ''), NULLIF(customName, ''), name)
            FROM subscriptions WHERE id = ?
            """,
            (sub_id,),
        ).fetchone()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    if not row or not row[0]:
        return None
    return str(row[0])


def _pub():
    import providers.incy as m  # noqa: PLC0415 — tests patch providers.incy

    return m


def incy_installed() -> bool:
    return _pub().incy_installed()


def _read_keeper_state() -> dict | None:
    try:
        data = json.loads(_pub().KEEPER_STATE.read_text())
    except OSError, json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _live_worker(state: dict | None) -> bool:
    try:
        pid = int((state or {}).get("xray_pid", 0))
        return pid > 0 and b"incy.launcher" in Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError, ValueError, TypeError:
        return False


def app_connected() -> bool:
    """The stock INCY app uses tun_incy; our broker exclusively owns incy-xray."""
    return _GUI_LINK.is_dir()


def _load_connections() -> list[VPNConnection]:
    db = _pub().INCY_DB
    if not db.is_file():
        return []
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.0)
    except sqlite3.Error:
        return []
    try:
        cur = conn.execute(
            """
            SELECT s.name,
                   s.subscriptionId,
                   s.isActive,
                   COALESCE(NULLIF(sub.profileName, ''), NULLIF(sub.customName, ''),
                             sub.name) AS sub_name
            FROM servers s
            LEFT JOIN subscriptions sub ON sub.id = s.subscriptionId
            WHERE sub.isEnabled IS NULL OR sub.isEnabled = 1
            ORDER BY COALESCE(sub.orderIndex, 0), s.orderIndex, s.name
            """
        )
        rows = cur.fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()

    state = _read_keeper_state()
    active_name = active_sub = None
    if state and state.get("status") == "connected" and _live_worker(state):
        active_name = state.get("server")
        active_sub = state.get("provider_id")
    elif _incy_link_up():
        for name, sub_id, is_active, _sub_name in rows:
            if is_active:
                active_name, active_sub = name, sub_id
                break

    conns: list[VPNConnection] = []
    for name, sub_id, _is_active, sub_name in rows:
        active = False
        if active_name:
            same_sub = not active_sub or sub_id == active_sub
            if same_sub and (name == active_name or active_name in name or name in active_name):
                active = True
        conns.append(
            VPNConnection(
                name=name,
                provider="INCY",
                active=active,
                interface=("tun_incy" if _GUI_LINK.is_dir() else TUN_IFACE) if active else None,
                subscription_id=sub_id or None,
                subscription_name=sub_name or None,
            )
        )
    return conns


def incy_server_groups(provider: VPNProvider) -> tuple[list[dict], dict[str, list[dict]]]:
    """Group by VPN vendor (profileName), like Happ's subscription provider_name."""
    groups: dict[str, list[dict]] = {}
    for c in provider.connections():
        title = c.subscription_name or "INCY"
        groups.setdefault(title, []).append(
            {
                "name": c.name,
                "active": c.active,
                "provider_id": c.subscription_id or "",
            }
        )
    return [], groups


class IncyProvider(VPNProvider):
    @property
    def name(self) -> str:
        return "INCY"

    def active_connections(self) -> list[VPNConnection]:
        state = _read_keeper_state()
        if (
            state
            and state.get("status") == "connected"
            and state.get("server")
            and _live_worker(state)
        ):
            sub_id = state.get("provider_id")
            return [
                VPNConnection(
                    name=state["server"],
                    provider=self.name,
                    active=True,
                    interface=TUN_IFACE,
                    subscription_id=sub_id,
                    subscription_name=_subscription_name(sub_id),
                )
            ]
        if not _incy_link_up():
            return []
        # INCY app-owned tunnel: full incy.db read (no plugin keeper state).
        return [c for c in _load_connections() if c.active]

    def connections(self) -> list[VPNConnection]:
        return _load_connections()

    def ping_targets(self) -> list[PingTarget]:
        from happ.servers import server_endpoints_of  # noqa: PLC0415
        from incy.subscriptions import all_db_catalog_entries  # noqa: PLC0415

        targets: list[PingTarget] = []
        for entry in all_db_catalog_entries():
            cfg = entry["config"]
            name = entry["name"]
            for host, port in server_endpoints_of(cfg):
                targets.append((name, host, port))
        return targets

    def connect(self, connection: VPNConnection) -> ActionResult:
        if not incy_installed():
            return ActionResult(
                False,
                "INCY native libraries not found — install incy-bin (AUR) or the official package, "
                "or set OMARCHY_VPN_INCY_ROOT to your INCY install",
            )
        if app_connected():
            return ActionResult(
                False,
                "INCY app connection — disconnect in INCY first (same rule as Happ app)",
            )
        sub_id = connection.subscription_id
        self._stop_running()
        return self._headless_connect(connection.name, sub_id)

    def _stop_running(self) -> None:
        pub = _pub()
        state = _read_keeper_state()
        pub.KEEPER_STATE.unlink(missing_ok=True)
        if state and (pid := state.get("pid")):
            try:
                if b"--incy-keeper" in Path(f"/proc/{int(pid)}/cmdline").read_bytes():
                    os.kill(int(pid), signal.SIGTERM)
            except OSError, ValueError, TypeError:
                pass
        if state and _live_worker(state):
            with contextlib.suppress(OSError):
                os.kill(int(state["xray_pid"]), signal.SIGTERM)
        deadline = time.time() + 5
        while time.time() < deadline:
            if not Path(f"/sys/class/net/{TUN_IFACE}").exists():
                return
            time.sleep(0.2)

    def _headless_connect(self, server_name: str, provider_id: str | None) -> ActionResult:
        pub = _pub()
        pub.KEEPER_STATE.unlink(missing_ok=True)
        manager = Path(__file__).resolve().parent.parent.parent / "vpn_manager.py"
        cmd = [sys.executable, str(manager), "--incy-keeper", server_name]
        if provider_id:
            cmd.append(provider_id)
        keeper = pub.subprocess.Popen(
            cmd,
            stdout=pub.subprocess.DEVNULL,
            stderr=pub.subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.time() + 40
        success = False
        try:
            result = self._await_keeper(deadline, keeper.pid)
            success = result.success
            return result
        finally:
            if not success:
                with contextlib.suppress(OSError):
                    keeper.terminate()

    def _await_keeper(self, deadline: float, pid: int) -> ActionResult:
        pub = _pub()
        while pub.time.time() < deadline:
            state = _read_keeper_state()
            if state and state.get("pid") == pid:
                if state.get("status") == "connected":
                    return ActionResult(True, f"Connected: {state.get('server', 'INCY')}")
                if state.get("status") == "error":
                    return ActionResult(False, state.get("message", "keeper error"))
                if state.get("status") == "exited":
                    return ActionResult(False, "keeper exited before connecting — see log")
            pub.time.sleep(0.2)
        return ActionResult(False, "keeper timeout — see log")

    def disconnect(self, connection: VPNConnection) -> ActionResult:
        if app_connected():
            return ActionResult(False, "Disconnect the INCY app connection in INCY first")
        if not Path(f"/sys/class/net/{TUN_IFACE}").exists() and not _read_keeper_state():
            return ActionResult(False, "INCY is not connected")
        self._stop_running()
        if Path(f"/sys/class/net/{TUN_IFACE}").exists():
            return ActionResult(False, "INCY disconnect timed out — see log")
        return ActionResult(True, "Disconnected INCY")

    def import_config(self, path: str) -> ActionResult:
        return ActionResult(
            False,
            "Import subscriptions in the INCY app (URL / QR); omarchy-vpn reads incy.db",
        )
