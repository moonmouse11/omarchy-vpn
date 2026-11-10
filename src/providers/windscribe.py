"""Shim — implementation in providers.vendor.windscribe."""

import shutil
import subprocess
import time

from providers.vendor.windscribe import WindscribeProvider


def _run(args: list[str], timeout: int = 15) -> tuple[int, str]:
    from providers.vendor import windscribe as impl  # noqa: PLC0415 — tests patch shim._run

    return impl._run(args, timeout)


def _interfaces() -> dict[str, int]:
    from providers.vendor import windscribe as impl  # noqa: PLC0415 — tests patch shim

    return impl._interfaces()


__all__ = ["WindscribeProvider", "_interfaces", "_run", "shutil", "subprocess", "time"]
