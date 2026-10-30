"""Shim — implementation in providers.classic.networkmanager."""

import shutil
import subprocess

from providers.classic.networkmanager import NetworkManagerProvider, _terse_lines


def _run(cmd: list[str]) -> tuple[int, str]:
    from providers.classic import networkmanager as impl  # noqa: PLC0415 — tests patch shim._run

    return impl._run(cmd)


__all__ = ["NetworkManagerProvider", "_run", "_terse_lines", "shutil", "subprocess"]
