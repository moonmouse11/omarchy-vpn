"""Cloudflare WARP via warp-cli (cloudflare-warp-bin, AUR).

The root warp-svc daemon owns all state; the user drives it without sudo.
One logical row: consumer WARP has no server choice.
"""

import re

from providers.common.types import ActionResult, VPNConnection, VPNProvider

_NAME = "Cloudflare WARP"
_IFACE = "CloudflareWARP"
_DAEMON_DOWN = "Unable to connect to the CloudflareWARP daemon"
TIMEOUT = 15
# `warp-cli connect` only accepts the command — the tunnel comes up later (or
# never). Wait this long for a real Connected before admitting defeat.
CONNECT_WAIT = 20.0
_CONNECT_POLL = 0.5

# "Status update: Connected" (2024+) or a bare "Connected" (older) — anchored so
# "Disconnected"/"Not Connected"/"Connecting" never match.
_CONNECTED = re.compile(r"^(?:Status update: )?Connected\b", re.M)


def _run(args: list[str], timeout: int = TIMEOUT) -> tuple[int, str]:
    from providers import warp  # noqa: PLC0415 — tests patch warp.subprocess

    try:
        result = warp.subprocess.run(
            ["warp-cli", *args], capture_output=True, text=True, timeout=timeout, check=False
        )
    except warp.subprocess.TimeoutExpired:
        return 1, f"timeout after {timeout}s: warp-cli {' '.join(args)}"
    return result.returncode, (result.stdout + result.stderr).strip()


def _daemon_down(text: str) -> bool:
    return _DAEMON_DOWN in text


class WarpProvider(VPNProvider):
    @property
    def name(self) -> str:
        return _NAME

    def _available(self) -> bool:
        from providers import warp  # noqa: PLC0415 — tests patch the shim

        return warp.shutil.which("warp-cli") is not None

    def _status(self) -> str | None:
        """Status text, or None when the daemon is down / the call failed."""
        from providers import warp  # noqa: PLC0415 — tests patch the shim

        code, out = warp._run(["status"])
        if code != 0 or _daemon_down(out):
            return None
        return out

    def _connected(self, status: str) -> bool:
        return _CONNECTED.search(status) is not None

    def connections(self) -> list[VPNConnection]:
        if not self._available():
            return []
        status = self._status()
        if status is None:
            return []
        active = self._connected(status)
        return [
            VPNConnection(
                name=_NAME,
                provider=self.name,
                active=active,
                interface=_IFACE if active else None,
            )
        ]

    def active_connections(self) -> list[VPNConnection]:
        # one `warp-cli status`, never a heavier scan — --status runs every 3 s
        return [c for c in self.connections() if c.active]

    def import_config(self, path: str) -> ActionResult:
        return ActionResult(False, "Cloudflare WARP has no config files to import")

    def setup_issue(self) -> dict | None:
        if not self._available():
            return {
                "hint": "Cloudflare WARP is not installed",
                "command": "yay -S cloudflare-warp-bin",
            }
        if self._status() is None:
            return {
                "hint": "The WARP daemon is not running",
                "command": "sudo systemctl enable --now warp-svc"
                " && warp-cli registration new",
            }
        if not self._registered():
            return {
                "hint": "WARP is not registered yet",
                "command": "warp-cli registration new",
            }
        return None

    def _registered(self) -> bool:
        # 2026.8 observed quirk: daemon-down `registration show` exits 0 with
        # the error text — parse the text, not just the rc.
        from providers import warp  # noqa: PLC0415 — tests patch the shim

        code, out = warp._run(["registration", "show"])
        return code == 0 and not _daemon_down(out) and "error" not in out.lower()

    def connect(self, connection: VPNConnection) -> ActionResult:
        from providers import warp  # noqa: PLC0415 — tests patch the shim

        if not self._available():
            return ActionResult(False, "warp-cli not found — install cloudflare-warp-bin (AUR)")
        code, out = warp._run(["status"])
        if _daemon_down(out):
            return ActionResult(
                False,
                "WARP daemon is not running — start it: "
                "sudo systemctl enable --now warp-svc.service",
            )
        if "timeout after" in out:
            return ActionResult(False, f"warp-cli timed out — {out}")
        if code != 0:
            return ActionResult(False, f"warp-cli status failed: {out}")
        if not self._registered():
            return ActionResult(False, "WARP is not registered — run: warp-cli registration new")
        code, out = warp._run(["connect"])
        if code != 0:
            return ActionResult(False, out or "warp-cli connect failed")
        return self._await_connected(warp)

    def _await_connected(self, warp) -> ActionResult:
        """connect is async: rc 0 = accepted. Poll until Connected; give up
        cleanly (disconnect) on Unable/timeout so no half-up state lingers."""
        deadline = warp.time.monotonic() + CONNECT_WAIT
        last = ""
        while warp.time.monotonic() < deadline:
            code, out = warp._run(["status"])
            if code == 0:
                if self._connected(out):
                    return ActionResult(True, "Connected")
                last = out
                if "unable" in out.lower() or "error" in out.lower():
                    break
            warp.time.sleep(_CONNECT_POLL)
        warp._run(["disconnect"])
        reason = last or "no status"
        return ActionResult(
            False,
            f"WARP did not connect in {CONNECT_WAIT:.0f}s ({reason}) — "
            "the network may be blocking Cloudflare WARP",
        )

    def disconnect(self, connection: VPNConnection) -> ActionResult:
        from providers import warp  # noqa: PLC0415 — tests patch the shim

        code, out = warp._run(["disconnect"])
        if code != 0:
            return ActionResult(False, out or "warp-cli disconnect failed")
        return ActionResult(True, "Disconnected")
