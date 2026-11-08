"""Shim — implementation in providers.vendor.warp."""

import shutil
import subprocess

from providers.vendor.warp import WarpProvider


def _run(args: list[str], timeout: int = 15) -> tuple[int, str]:
    from providers.vendor import warp as impl  # noqa: PLC0415 — tests patch shim._run

    return impl._run(args, timeout)


__all__ = ["WarpProvider", "_run", "shutil", "subprocess"]
