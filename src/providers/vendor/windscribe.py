"""Windscribe via windscribe-cli (AUR: windscribe-cli-v2-bin / windscribe-v2-bin).

The root windscribeservice daemon owns all state; the user drives it without sudo.
Free-tier accounts work — that is the point of this provider.
"""

import re

from providers.common.types import ActionResult, VPNConnection, VPNProvider

_NAME = "Windscribe"
TIMEOUT = 15
# `windscribe-cli connect` only accepts the command — poll for the real state
# (same async contract as the WARP provider).
CONNECT_WAIT = 20.0
_CONNECT_POLL = 0.5
# whole words: 'Unlimited' (a normal Pro status) must never read as a failure
_FAILURE_MARKERS = re.compile(r"\b(error|unable|upgrade|exceed|limit|fail)\b")
_LOGGED_OUT_MARKERS = ("not logged in", "logged out", "please log in", "login required")
# v2 (2.21.7) pins key-value status lines: 'Login state:', 'Connect state:',
# 'Location:', 'Firewall state:' — and flat location rows
# 'US East - New York - Empire (Pro) (10 Gbps)'.
_GBPS_SUFFIX = re.compile(r"\s*\(\d+ Gbps\)\s*$")
_PRO_MARK = " (Pro)"


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
    """Display names from `windscribe-cli locations` (v2: flat rows,
    'Region - City - Nickname (Pro)? (10 Gbps)') — the speed suffix is uniform
    noise, the (Pro) mark stays: free users must see what they can't use."""
    rows: list[str] = []
    for line in text.splitlines():
        row = _GBPS_SUFFIX.sub("", line.strip())
        if row:
            rows.append(row)
    return rows


def _nickname(name: str) -> str:
    """connect takes a nickname (or city/region/ISO), never the display label:
    'US East - New York - Empire (Pro)' → 'Empire'."""
    return name.removesuffix(_PRO_MARK).rsplit(" - ", 1)[-1]


def _kv(status: str, key: str) -> str | None:
    for line in status.splitlines():
        label, _, value = line.partition(":")
        if label.strip().lower() == key:
            return value.strip()
    return None


class WindscribeProvider(VPNProvider):
    can_logout = True

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
        """Unknown is logged OUT (never refuse silently, never connect anonymously).
        v2 pins a key-value 'Login state:' line; older wordings fall back to markers."""
        status = self._status()
        if status is None:
            return False
        for line in status.lower().splitlines():
            label, _, state = line.partition(":")
            if label.strip() == "login state":
                return state.strip() == "logged in"
        return not any(m in status.lower() for m in _LOGGED_OUT_MARKERS)

    def _connected_label(self, status: str) -> str | None:
        """The display name of the connected location, or None."""
        state = _kv(status, "connect state")
        if state is None or not state.lower().startswith("connected"):
            return None
        return _kv(status, "location") or _NAME

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
                active=(label is not None and row.removesuffix(_PRO_MARK) == label),
                interface=(
                    "Windscribe"
                    if label is not None and row.removesuffix(_PRO_MARK) == label
                    else None
                ),
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
        if not self._available():
            return None
        status = self._status()
        if status is None or (_kv(status, "firewall state") or "").lower() != "on":
            return None
        return (
            "Windscribe's own firewall is ON — it may keep blocking traffic "
            "after this disconnect. Turn it off: windscribe-cli firewall off"
        )

    def logout(self) -> ActionResult:
        from providers import windscribe  # noqa: PLC0415 — tests patch the shim

        code, out = windscribe._run(["logout"])
        if code != 0:
            return ActionResult(False, out or "windscribe-cli logout failed")
        return ActionResult(True, "Logged out")

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
        code, out = windscribe._run(["connect", _nickname(connection.name)])
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
                label = self._connected_label(out)
                if label is not None and (
                    label == name.removesuffix(_PRO_MARK) or _nickname(label) == _nickname(name)
                ):
                    return ActionResult(True, f"Connected to {label}")
                last = out
                if _FAILURE_MARKERS.search(out.lower()):
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
