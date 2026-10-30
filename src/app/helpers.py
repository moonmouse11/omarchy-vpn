"""Shared helpers (notify, refresh bar, background targets)."""

import contextlib
import subprocess

import happmeta
import logutil
import notifyutil
from app.registry import PLUGIN_ID
from providers import ALL_PROVIDERS

# ── Helpers ───────────────────────────────────────────────────────────────────


def _collect_ping_targets() -> list[tuple[str, str, int]]:
    """Happ + every provider's ping targets for one --update-ping sweep.

    One broken provider must not stop the others (pattern:
    happmeta.update_subscriptions), so a raising ping_targets() is skipped."""
    targets = happmeta.ping_targets()
    for provider in ALL_PROVIDERS:
        try:
            targets += provider.ping_targets()
        except Exception as e:  # noqa: BLE001 — one broken provider must not stop the rest
            logutil.log(f"ping targets: {provider.name} skipped: {e!r}")
            continue
    return targets


def notify(title: str, message: str, urgent: bool = False):
    # title/message can carry a VPN daemon's own error text or a
    # subscription provider's server name — notifyutil cleans both
    notifyutil.send(title, message, urgent=urgent)


def refresh_bar():
    """Re-run the bar widget's --status now instead of on its next tick.
    -q: best effort — no shell running, or the widget not on the bar, is fine."""
    with contextlib.suppress(OSError, subprocess.TimeoutExpired):
        subprocess.run(
            ["omarchy-shell", "-q", PLUGIN_ID, "refresh"],
            capture_output=True,
            timeout=5,
            check=False,
        )
