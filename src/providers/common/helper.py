import contextlib
import signal
import subprocess


def _base():
    from providers import base  # noqa: PLC0415 — tests patch base.subprocess / base.os

    return base


# The one root entry point for WireGuard/AmneziaWG/OpenVPN (scripts/omarchy-vpn-helper,
# installed by install.sh): profile names only, never paths — the old sudoers rule
# (`wg-quick *`, `cp * /etc/wireguard/*`, `cat …`, `kill`) was root for any process.
HELPER = "/usr/local/bin/omarchy-vpn-helper"
# config directory -> the helper's KIND
HELPER_KINDS = {
    "/etc/wireguard": "wg",
    "/etc/amnezia/amneziawg": "awg",
    "/etc/openvpn/client": "ovpn",
}


_helper_slot: list[subprocess.Popen[str] | None] = [None]


def terminate_registered_subprocesses() -> None:
    """Stop a long `run_helper()` still in flight (switch superseded it)."""
    proc = _helper_slot[0]
    _helper_slot[0] = None
    if proc is None or proc.poll() is not None:
        return
    base = _base()
    with contextlib.suppress(OSError, ProcessLookupError):
        base.os.killpg(base.os.getpgid(proc.pid), signal.SIGTERM)
    try:
        proc.wait(timeout=2)
    except base.subprocess.TimeoutExpired:
        with contextlib.suppress(OSError, ProcessLookupError):
            base.os.killpg(base.os.getpgid(proc.pid), signal.SIGKILL)
        with contextlib.suppress(base.subprocess.TimeoutExpired):
            proc.wait(timeout=1)


def run_helper(*args: str, stdin: str | None = None, timeout: float = 60) -> tuple[int, str]:
    """`sudo -n omarchy-vpn-helper ARGS` → (returncode, stdout+stderr).

    Polls instead of subprocess.run so SIGTERM from a superseding switch can
    run terminate_registered_subprocesses() and drop a stuck sudo/awg-quick."""
    base = _base()
    subp = base.subprocess
    try:
        proc = subp.Popen(
            ["sudo", "-n", HELPER, *args],
            stdin=subp.PIPE if stdin is not None else subp.DEVNULL,
            stdout=subp.PIPE,
            stderr=subp.STDOUT,
            text=True,
            errors="replace",
            start_new_session=True,
        )
    except OSError as e:
        return 1, str(e)
    _helper_slot[0] = proc
    try:
        if stdin is not None and proc.stdin:
            proc.stdin.write(stdin)
            proc.stdin.close()
        deadline = base.time.monotonic() + timeout
        while proc.poll() is None:
            if base.time.monotonic() >= deadline:
                base.terminate_registered_subprocesses()
                return 1, "timeout"
            base.time.sleep(0.05)
        if proc.stdout is None:
            return proc.returncode or 0, ""
        out = proc.stdout.read()
        return proc.returncode or 0, out.strip()
    except OSError as e:
        base.terminate_registered_subprocesses()
        return 1, str(e)
    finally:
        _helper_slot[0] = None


def read_config_text(path) -> str | None:
    """Text of a provider config: direct read first, else the helper's
    `endpoints` (configs are root:0600) — only the Endpoint/remote lines and
    section headers, never the keys, which is all the ping and the kill
    switch whitelist read. None when neither works."""
    base = _base()
    p = base.Path(path)
    try:
        return p.read_text(errors="replace")
    except OSError:
        pass
    kind = HELPER_KINDS.get(str(p.parent))
    if kind is None:
        return None
    code, out = base.run_helper("endpoints", kind, p.stem, timeout=10)
    return out if code == 0 else None
