"""Windscribe via windscribe-cli (AUR: windscribe-cli-v2-bin / windscribe-v2-bin).

The root windscribeservice daemon owns all state; the user drives it without sudo.
Free-tier accounts work — that is the point of this provider.
"""

import contextlib
import re
from dataclasses import dataclass
from pathlib import Path

import config
from providers.common import interfaceclaims
from providers.common.types import ActionResult, VPNConnection, VPNProvider
from providers.vendor.windscribe_lock import CliBusyError, cli_lock
from providers.vendor.windscribe_status import WindscribeStatus, parse_status
from windscribeprefs import normalize_port, normalize_protocol

_NAME = "Windscribe"
TIMEOUT = 15
# `connect -n` only accepts the command — poll for the real state
# (same async contract as the WARP provider).
CONNECT_WAIT = 35.0
DISCONNECT_WAIT = 15.0
_CONNECT_POLL = 0.5
_PROTOCOLS: tuple[str | None, ...] = (None, "stealth", "wstunnel")
# whole words: 'Unlimited' (a normal Pro status) must never read as a failure
_FAILURE_MARKERS = re.compile(r"\b(error|unable|upgrade|exceed|limit|fail)\b")
# v2 (2.21.7) pins key-value status lines: 'Login state:', 'Connect state:',
# 'Location:', 'Firewall state:' — and flat location rows
# 'US East - New York - Empire (Pro) (10 Gbps)'.
_PRO_MARK = " (Pro)"
_LOCATION_FLAGS = (("(Pro)", "pro"), ("(Disabled)", "disabled"), ("(10 Gbps)", "ten_gbps"))
_SYS_NET = Path("/sys/class/net")
COMPATIBILITY_MESSAGE = "Windscribe CLI output is not recognized; the plugin may need an update"
_UNKNOWN_CONNECTION = "Windscribe connection (status unknown)"


def _interfaces() -> dict[str, int]:
    try:
        paths = list(_SYS_NET.iterdir())
    except OSError:
        return {}
    interfaces = {}
    for path in paths:
        try:
            interfaces[path.name] = int((path / "ifindex").read_text())
        except OSError, ValueError:
            continue
    return interfaces


def _run(args: list[str], timeout: int = TIMEOUT) -> tuple[int, str]:
    from providers import windscribe  # noqa: PLC0415 — tests patch windscribe.subprocess

    try:
        with cli_lock(timeout):
            result = windscribe.subprocess.run(
                ["windscribe-cli", *args],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
    except CliBusyError as e:
        return 1, str(e)
    except windscribe.subprocess.TimeoutExpired:
        return 1, f"timeout after {timeout}s: windscribe-cli {' '.join(args)}"
    return result.returncode, (result.stdout + result.stderr).strip()


@dataclass(frozen=True)
class WindscribeLocation:
    name: str
    region: str
    city: str
    nickname: str
    pro: bool = False
    disabled: bool = False
    ten_gbps: bool = False


def _location_rows(text: str) -> list[WindscribeLocation]:
    """Structured rows from the documented flat locations output."""
    parsed: dict[tuple[str, str, str], tuple[str, str, str, dict[str, bool]]] = {}
    for raw in text.splitlines():
        line = raw.rstrip()
        flags = {"pro": False, "disabled": False, "ten_gbps": False}
        changed = True
        while changed:
            changed = False
            for suffix, flag_name in _LOCATION_FLAGS:
                if line.lower().endswith(suffix.lower()):
                    flags[flag_name] = True
                    line = line[: -len(suffix)].rstrip()
                    changed = True
                    break
        parts = [part.strip() for part in line.split(" - ")]
        if len(parts) < 3 or not all(parts) or parts[0].lower() == "best location":
            continue
        region, city = parts[:2]
        nickname = " - ".join(parts[2:])
        identity = (region.lower(), city.lower(), nickname.lower())
        if identity in parsed:
            existing = parsed[identity][3]
            for flag_name, enabled in flags.items():
                existing[flag_name] = existing[flag_name] or enabled
            continue
        parsed[identity] = (region, city, nickname, flags)

    rows = []
    for region, city, nickname, flags in parsed.values():
        name = " - ".join((region, city, nickname))
        if flags["pro"]:
            name += _PRO_MARK
        rows.append(WindscribeLocation(name, region, city, nickname, **flags))
    return rows


def _connect_target(name: str) -> str | None:
    """Use the city, or reject a row/status label with no recognizable target."""
    parts = [part.strip() for part in name.removesuffix(_PRO_MARK).split(" - ")]
    if parts[0] == "Best Location":
        return "best"
    if len(parts) >= 3 and all(parts):
        return parts[1]
    return parts[0] if len(parts) == 2 and all(parts) else None


def _protocol_label(status: WindscribeStatus) -> str | None:
    if not status.protocol:
        return None
    labels = {"wireguard": "WireGuard", "wstunnel": "WStunnel"}
    label = labels.get(status.protocol, status.protocol.capitalize())
    return f"{label}:{status.port}" if status.port else label


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

    def _status_state(self) -> WindscribeStatus | None:
        status = self._status()
        return parse_status(status) if status is not None else None

    def _connected_label(self, status: WindscribeStatus) -> str | None:
        """The display name of the connected location, or None."""
        if status.connection_state != "connected":
            return None
        return status.location or _NAME

    def connections(self) -> list[VPNConnection]:
        from providers import windscribe  # noqa: PLC0415 — tests patch the shim

        if not self._available():
            return []
        status = self._status_state()
        if status is None or not status.recognized or status.login_state != "logged_in":
            return []
        label = self._connected_label(status)
        interface = interfaceclaims.get(self.name) if label is not None else None
        protocol = _protocol_label(status) if label is not None and status is not None else None
        code, out = windscribe._run(["locations"])
        if code != 0:
            return []
        connections = [
            VPNConnection(
                name="Best Location",
                provider=self.name,
                active=False,
                metadata={"synthetic": True},
            )
        ]
        for row in _location_rows(out):
            active = label is not None and row.name.removesuffix(_PRO_MARK) == label
            connections.append(
                VPNConnection(
                    name=row.name,
                    provider=self.name,
                    active=active,
                    interface=interface if active else None,
                    protocol=protocol if active else None,
                    metadata={
                        "region": row.region,
                        "city": row.city,
                        "nickname": row.nickname,
                        "pro": row.pro,
                        "disabled": row.disabled,
                        "ten_gbps": row.ten_gbps,
                    },
                )
            )
        return connections

    def active_connections(self) -> list[VPNConnection]:
        # one `windscribe-cli status`, never a locations scan — --status runs every 3 s
        if not self._available():
            return []
        status = self._status_state()
        if status is None:
            return []
        interface = interfaceclaims.get(self.name)
        if not status.recognized:
            return [
                VPNConnection(
                    name=_UNKNOWN_CONNECTION,
                    provider=self.name,
                    active=True,
                    interface=interface,
                )
            ]
        label = self._connected_label(status)
        if label is None:
            return []
        return [
            VPNConnection(
                name=label,
                provider=self.name,
                active=True,
                interface=interface,
                protocol=_protocol_label(status),
            )
        ]

    def setup_issue(self) -> dict | None:
        if not self._available():
            return {
                "hint": "Windscribe is not installed",
                "command": "yay -S windscribe-cli-v2-bin",
            }
        status = self._status_state()
        if status is not None and not status.recognized:
            return {"hint": COMPATIBILITY_MESSAGE, "command": "windscribe-cli status"}
        if status is None or status.login_state != "logged_in":
            return {
                "hint": "Windscribe needs your account login",
                "command": "windscribe-cli login",
            }
        return None

    def lockdown_hint(self, connection: VPNConnection) -> str | None:
        if not self._available():
            return None
        status = self._status_state()
        if status is None or not status.recognized or status.firewall not in ("on", "always_on"):
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
        preferences = config.load_config()
        protocol = normalize_protocol(preferences.windscribe_protocol)
        port = normalize_port(preferences.windscribe_port)
        status = self._status_state()
        if status is not None and not status.recognized:
            return ActionResult(False, COMPATIBILITY_MESSAGE)
        if status is None or status.login_state != "logged_in":
            return ActionResult(False, "Not logged in — run: windscribe-cli login")
        if connection.metadata.get("disabled") is True:
            return ActionResult(False, "This Windscribe location is disabled")
        target = _connect_target(connection.name)
        if target is None:
            return ActionResult(False, "Unrecognized Windscribe location; refresh the server list")
        previous = interfaceclaims.get(self.name)
        before = windscribe._interfaces()
        last = ActionResult(False, "windscribe-cli connect failed")
        protocols = (
            _PROTOCOLS if protocol == "automatic" else (f"{protocol}:{port}" if port else protocol,)
        )
        for attempt_protocol in protocols:
            args = ["connect", "-n", target]
            if attempt_protocol is not None:
                args.append(attempt_protocol)
            code, out = windscribe._run(args)
            if code != 0:
                last = ActionResult(False, out or "windscribe-cli connect failed")
                continue
            last, stopped = self._await_connected(windscribe, connection.name)
            if last.success:
                self._record_interface_claim(windscribe, previous, before)
                return last
            if not stopped:
                break
        if previous is None:
            with contextlib.suppress(OSError):
                interfaceclaims.release(self.name)
        return last

    def _record_interface_claim(
        self, windscribe, previous: str | None, before: dict[str, int]
    ) -> None:
        after = windscribe._interfaces()
        created = {name for name, inode in after.items() if before.get(name) != inode}
        with contextlib.suppress(OSError):
            if previous is not None and interfaceclaims.get(self.name) == previous:
                return
            if len(created) == 1:
                interfaceclaims.claim(self.name, created.pop())
            else:
                interfaceclaims.release(self.name)

    def _await_connected(self, windscribe, name: str) -> tuple[ActionResult, bool]:
        """connect is async: rc 0 = accepted. Poll until this location is the
        connected one; disconnect on vendor refusal/timeout (no half-up state)."""
        deadline = windscribe.time.monotonic() + CONNECT_WAIT
        target = _connect_target(name)
        last = ""
        while windscribe.time.monotonic() < deadline:
            code, out = windscribe._run(["status"])
            if code == 0:
                status = parse_status(out)
                if not status.recognized:
                    last = COMPATIBILITY_MESSAGE
                    break
                label = self._connected_label(status)
                if (
                    label is not None
                    and target is not None
                    and (label == name.removesuffix(_PRO_MARK) or _connect_target(label) == target)
                ):
                    return ActionResult(True, f"Connected to {label}"), True
                last = out
                if _FAILURE_MARKERS.search(out.lower()):
                    break
            windscribe.time.sleep(_CONNECT_POLL)
        if not self._disconnect_and_wait(windscribe).success:
            return ActionResult(False, "Windscribe did not disconnect; fallback stopped"), False
        reason = last or "no status"
        return (
            ActionResult(False, f"Windscribe did not connect in {CONNECT_WAIT:.0f}s ({reason})"),
            True,
        )

    def _disconnect_and_wait(self, windscribe) -> ActionResult:
        """The CLI acknowledges disconnect before its tunnel has stopped."""
        code, out = windscribe._run(["disconnect"])
        if code != 0:
            return ActionResult(False, out or "windscribe-cli disconnect failed")
        deadline = windscribe.time.monotonic() + DISCONNECT_WAIT
        while windscribe.time.monotonic() < deadline:
            code, output = windscribe._run(["status"])
            if code == 0:
                status = parse_status(output)
                if not status.recognized:
                    return ActionResult(False, COMPATIBILITY_MESSAGE)
                if status.connection_state == "disconnected":
                    return ActionResult(True, "Disconnected")
            windscribe.time.sleep(_CONNECT_POLL)
        return ActionResult(False, "Windscribe did not disconnect; tunnel may still be active")

    def disconnect(self, connection: VPNConnection) -> ActionResult:
        from providers import windscribe  # noqa: PLC0415 — tests patch the shim

        # Keep ownership until the interface disappears, and don't let a
        # provider switch proceed on an acknowledgement before actual teardown.
        return self._disconnect_and_wait(windscribe)
