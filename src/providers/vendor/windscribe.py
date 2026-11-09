"""Windscribe via windscribe-cli (AUR: windscribe-cli-v2-bin / windscribe-v2-bin).

The root windscribeservice daemon owns all state; the user drives it without sudo.
Free-tier accounts work — that is the point of this provider.
"""

from providers.common.types import ActionResult, VPNConnection, VPNProvider

_NAME = "Windscribe"
TIMEOUT = 15
# `windscribe-cli connect` only accepts the command — poll for the real state
# (same async contract as the WARP provider).
CONNECT_WAIT = 20.0
_CONNECT_POLL = 0.5
_FAILURE_MARKERS = ("error", "unable", "upgrade", "exceed", "limit", "fail")
_CONNECTED_PREFIX = "Windscribe: Connected to "
_LOGGED_OUT_MARKERS = ("not logged in", "please log in", "login required")


def _run(args: list[str], timeout: int = TIMEOUT) -> tuple[int, str]:
    from providers import windscribe  # noqa: PLC0415 — tests patch windscribe.subprocess

    try:
        result = windscribe.subprocess.run(
            ["windscribe-cli", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except windscribe.subprocess.TimeoutExpired:
        return 1, f"timeout after {timeout}s: windscribe-cli {' '.join(args)}"
    return result.returncode, (result.stdout + result.stderr).strip()


def _locations(text: str) -> list[str]:
    """Connectable labels from `windscribe-cli locations`: skip headers, section
    titles (country groups) and separators — the indented entries are the locations."""
    rows: list[str] = []
    for line in text.splitlines():
        row = line.strip()
        if not row or set(row) <= {"-", "="}:
            continue
        if " - " not in row:  # header ("Locations") or country section ("Canada East")
            continue
        rows.append(row)
    return rows


class WindscribeProvider(VPNProvider):
    @property
    def name(self) -> str:
        return _NAME

    def _available(self) -> bool:
        from providers import windscribe  # noqa: PLC0415 — tests patch the shim

        return windscribe.shutil.which("windscribe-cli") is not None

    def _status(self) -> str | None:
        """Status text, or None when the call failed / the daemon is unreachable."""
        from providers import windscribe  # noqa: PLC0415 — tests patch the shim

        code, out = windscribe._run(["status"])
        if code != 0:
            return None
        return out

    def _logged_in(self) -> bool:
        """Unknown is logged OUT (never refuse silently, never connect anonymously)."""
        status = self._status()
        if status is None:
            return False
        return not any(m in status.lower() for m in _LOGGED_OUT_MARKERS)

    def _connected_label(self, status: str) -> str | None:
        for line in status.splitlines():
            if line.startswith(_CONNECTED_PREFIX):
                return line.removeprefix(_CONNECTED_PREFIX).strip() or None
        return None

    def connections(self) -> list[VPNConnection]:
        from providers import windscribe  # noqa: PLC0415 — tests patch the shim

        if not self._available() or not self._logged_in():
            return []
        status = self._status()
        label = self._connected_label(status or "")
        code, out = windscribe._run(["locations"])
        if code != 0:
            return []
        return [
            VPNConnection(
                name=row,
                provider=self.name,
                active=row == label,
                interface="Windscribe" if row == label else None,
            )
            for row in _locations(out)
        ]

    def active_connections(self) -> list[VPNConnection]:
        # one `windscribe-cli status`, never a locations scan — --status runs every 3 s
        if not self._available():
            return []
        status = self._status()
        label = self._connected_label(status or "")
        if label is None:
            return []
        return [VPNConnection(name=label, provider=self.name, active=True, interface="Windscribe")]

    def setup_issue(self) -> dict | None:
        if not self._available():
            return {
                "hint": "Windscribe is not installed",
                "command": "yay -S windscribe-cli-v2-bin",
            }
        if not self._logged_in():
            return {
                "hint": "Windscribe needs your account login",
                "command": "windscribe-cli login",
            }
        return None

    def lockdown_hint(self, connection: VPNConnection) -> str | None:
        from providers import windscribe  # noqa: PLC0415 — tests patch the shim

        if not self._available():
            return None
        code, out = windscribe._run(["firewall"])
        if code != 0 or "on" not in out.lower().replace("auto", ""):
            return None
        return (
            "Windscribe's own firewall is ON — it may keep blocking traffic "
            "after this disconnect. Turn it off: windscribe-cli firewall off"
        )

    def import_config(self, path: str) -> ActionResult:
        return ActionResult(False, "Windscribe has no config files to import")

    def connect(self, connection: VPNConnection) -> ActionResult:
        from providers import windscribe  # noqa: PLC0415 — tests patch the shim

        if not self._available():
            return ActionResult(
                False, "windscribe-cli not found — install windscribe-cli-v2-bin (AUR)"
            )
        if not self._logged_in():
            return ActionResult(False, "Not logged in — run: windscribe-cli login")
        code, out = windscribe._run(["connect", connection.name])
        if code != 0:
            return ActionResult(False, out or "windscribe-cli connect failed")
        return self._await_connected(windscribe, connection.name)

    def _await_connected(self, windscribe, name: str) -> ActionResult:
        """connect is async: rc 0 = accepted. Poll until this location is the
        connected one; disconnect on vendor refusal/timeout (no half-up state)."""
        deadline = windscribe.time.monotonic() + CONNECT_WAIT
        last = ""
        while windscribe.time.monotonic() < deadline:
            code, out = windscribe._run(["status"])
            if code == 0:
                if self._connected_label(out) == name:
                    return ActionResult(True, f"Connected to {name}")
                last = out
                if any(m in out.lower() for m in _FAILURE_MARKERS):
                    break
            windscribe.time.sleep(_CONNECT_POLL)
        windscribe._run(["disconnect"])
        reason = last or "no status"
        return ActionResult(False, f"Windscribe did not connect in {CONNECT_WAIT:.0f}s ({reason})")

    def disconnect(self, connection: VPNConnection) -> ActionResult:
        from providers import windscribe  # noqa: PLC0415 — tests patch the shim

        code, out = windscribe._run(["disconnect"])
        if code != 0:
            return ActionResult(False, out or "windscribe-cli disconnect failed")
        return ActionResult(True, "Disconnected")
