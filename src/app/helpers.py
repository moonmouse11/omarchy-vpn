"""Shared helpers (notify, refresh bar, background targets)."""

import contextlib
import subprocess
import sys

import happmeta
import logutil
import notifyutil
from app.registry import PLUGIN_ID, _provider_pool
from happ.constants import MANAGER

# ── Helpers ───────────────────────────────────────────────────────────────────


def spawn_manager(*flags: str) -> None:
    """Detached background vpn_manager.py (DNS autotest, exit IP, subs refresh)."""
    subprocess.Popen(
        [sys.executable, str(MANAGER), *flags],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def _collect_ping_targets() -> list[tuple[str, str, int]]:
    """Happ + every provider's ping targets for one --update-ping sweep.

    One broken provider must not stop the others (pattern:
    happmeta.update_subscriptions), so a raising ping_targets() is skipped."""
    targets = happmeta.ping_targets()
    for provider in _provider_pool():
        try:
            targets += provider.ping_targets()
        except Exception as e:  # noqa: BLE001 — one broken provider must not stop the rest
            logutil.log(f"ping targets: {provider.name} skipped: {e!r}")
            continue
    return targets


def notify(title: str, message: str, urgent: bool = False):
    import vpn_manager as vm  # noqa: PLC0415 — tests patch vpn_manager.notify

    remote = getattr(vm, "notify", None)
    if remote is not None and remote is not notify:
        remote(title, message, urgent=urgent)
        return
    # title/message can carry a VPN daemon's own error text or a
    # subscription provider's server name — notifyutil cleans both
    notifyutil.send(title, message, urgent=urgent)


def refresh_bar():
    """Re-run the bar widget's --status now instead of on its next tick.
    -q: best effort — no shell running, or the widget not on the bar, is fine."""
    import vpn_manager as vm  # noqa: PLC0415 — tests patch vpn_manager.refresh_bar

    remote = getattr(vm, "refresh_bar", None)
    if remote is not None and remote is not refresh_bar:
        remote()
        return
    with contextlib.suppress(OSError, subprocess.TimeoutExpired):
        subprocess.run(
            ["omarchy-shell", "-q", PLUGIN_ID, "refresh"],
            capture_output=True,
            timeout=5,
            check=False,
        )
