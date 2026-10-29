import subprocess
from pathlib import Path

from .base import ActionResult, VPNConnection, VPNProvider, read_config_text, run_helper

TIMEOUT = 6


def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        return 1, f"timeout after {TIMEOUT}s: {' '.join(cmd)}"
    return result.returncode, (result.stdout + result.stderr).strip()


OVPN_DIR = Path("/etc/openvpn/client")
PID_DIR = Path("/run/openvpn")


def _pid_file(profile: str) -> Path:
    return PID_DIR / f"client-{profile}.pid"


def _is_running(profile: str) -> bool:
    pid_file = _pid_file(profile)
    if not pid_file.exists():
        return False
    try:
        pid = int(pid_file.read_text().strip())
        return Path(f"/proc/{pid}").exists()
    except ValueError, OSError:
        return False


def ovpn_endpoint(conf_path) -> tuple[str, int] | None:
    """(host, port) of the first valid 'remote host port' directive.

    A remote without a numeric port, or commented out (; or #), yields None.
    The port must be <= 65535 — socket.create_connection raises
    OverflowError beyond that, which would abort a whole ping sweep."""
    text = read_config_text(conf_path)
    if text is None:
        return None
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith((";", "#")):
            continue
        parts = s.split()
        if parts[0].lower() != "remote":
            continue
        if len(parts) < 3 or not parts[2].isdigit():
            return None  # first remote unusable -> no endpoint for this config
        port = int(parts[2])
        return (parts[1], port) if port <= 65535 else None
    return None


class OpenVPNProvider(VPNProvider):
    @property
    def name(self) -> str:
        return "OpenVPN"

    def connections(self) -> list[VPNConnection]:
        result: list[VPNConnection] = []

        if not OVPN_DIR.exists():
            return result

        for conf in sorted(OVPN_DIR.glob("*.conf")) + sorted(OVPN_DIR.glob("*.ovpn")):
            profile = conf.stem
            is_active = _is_running(profile)
            result.append(
                VPNConnection(
                    name=profile,
                    provider=self.name,
                    active=is_active,
                    interface="tun0" if is_active else None,
                    config_path=str(conf),
                )
            )

        return result

    def ping_targets(self) -> list[tuple[str, str, int]]:
        targets = []
        for conn in self.connections():
            if not conn.config_path:
                continue
            ep = ovpn_endpoint(conn.config_path)
            if ep:
                targets.append((conn.name, ep[0], ep[1]))
        return targets

    def connect(self, connection: VPNConnection) -> ActionResult:
        # omarchy-vpn-helper runs openvpn with fixed flags: --daemon, the PID
        # file, openvpn-dns-updown as --up/--down (--script-security 2), and
        # --persist-remote-ip (a ping-restart can't resolve `remote` again
        # under the kill switch)
        code, out = run_helper("up", "ovpn", connection.name)
        if code != 0:
            return ActionResult(success=False, message=out)
        return ActionResult(success=True, message=f"Connected: {connection.name}")

    def disconnect(self, connection: VPNConnection) -> ActionResult:
        # the helper reads the PID file itself and kills only an openvpn
        code, out = run_helper("down", "ovpn", connection.name)
        if code != 0:
            return ActionResult(success=False, message=out.removeprefix("error: ").capitalize())
        return ActionResult(success=True, message=f"Disconnected: {connection.name}")

    def import_config(self, path: str) -> ActionResult:
        src = Path(path)
        if not src.exists():
            return ActionResult(success=False, message=f"File not found: {path}")
        if src.suffix not in (".conf", ".ovpn"):
            return ActionResult(success=False, message="File must have .conf or .ovpn extension")

        if any((OVPN_DIR / f"{src.stem}{ext}").exists() for ext in (".conf", ".ovpn")):
            return ActionResult(success=False, message=f"Config already exists: {src.stem}")
        try:
            text = src.read_text(errors="replace")
        except OSError as e:
            return ActionResult(success=False, message=f"Cannot read {path}: {e}")

        # the helper writes it as <name>.conf, 0600, and refuses configs that
        # run scripts or write files as root (up, route-up, plugin, log, …)
        code, out = run_helper("import", "ovpn", src.stem, stdin=text)
        if code != 0:
            return ActionResult(success=False, message=out.removeprefix("error: "))

        return ActionResult(success=True, message=f"Imported: {src.name}")

    def autostart_enabled(self, profile: str) -> bool:
        code, _ = _run(["systemctl", "is-enabled", f"openvpn-client@{profile}"])
        return code == 0

    def toggle_autostart(self, connection: VPNConnection) -> ActionResult:
        if connection.active:
            return ActionResult(False, f"Disconnect {connection.name} first")
        enabled = self.autostart_enabled(connection.name)
        code, out = run_helper("autostart", "ovpn", connection.name, "off" if enabled else "on")
        if code != 0:
            return ActionResult(False, f"Failed to toggle autostart: {out}")
        state = "disabled" if enabled else "enabled"
        return ActionResult(True, f"Autostart {state}: {connection.name}")

    def delete_config(self, connection: VPNConnection) -> ActionResult:
        if connection.active:
            return ActionResult(False, f"Disconnect {connection.name} first")
        if not any((OVPN_DIR / f"{connection.name}{ext}").exists() for ext in (".conf", ".ovpn")):
            return ActionResult(False, f"Config not found: {connection.name}")
        code, out = run_helper("rm", "ovpn", connection.name)
        if code != 0:
            return ActionResult(False, f"Failed to delete {connection.name}: {out}")
        return ActionResult(True, f"Deleted: {connection.name}")
