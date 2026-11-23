"""Bounded text reads from the Wayland clipboard owner."""

from __future__ import annotations

import os
import selectors
import subprocess
import time

DEFAULT_COMMAND = ("wl-paste", "--no-newline", "--type", "text")


class ClipboardReadError(Exception):
    pass


def _reap(process: subprocess.Popen[bytes], deadline: float) -> None:
    if process.poll() is not None:
        process.wait()
        return
    process.terminate()
    grace = max(0.0, min(0.05, deadline - time.monotonic()))
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def read_text(
    max_bytes: int,
    timeout: float = 2.0,
    *,
    command: tuple[str, ...] = DEFAULT_COMMAND,
) -> str:
    """Read one complete clipboard value within a byte bound and total deadline."""
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")

    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as error:
        raise ClipboardReadError("clipboard unavailable") from error

    payload = bytearray()
    try:
        if process.stdout is None:  # pragma: no cover - guaranteed by PIPE
            raise ClipboardReadError("clipboard unavailable")
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise ClipboardReadError("timed out")
                try:
                    chunk = os.read(process.stdout.fileno(), max_bytes + 1 - len(payload))
                except OSError as error:
                    raise ClipboardReadError("clipboard unavailable") from error
                if not chunk:
                    break
                payload.extend(chunk)
                if len(payload) > max_bytes:
                    raise ClipboardReadError("too large")

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ClipboardReadError("timed out")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise ClipboardReadError("timed out") from error
        if returncode != 0:
            raise ClipboardReadError("clipboard unavailable")
    finally:
        _reap(process, deadline)

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ClipboardReadError("not UTF-8") from error
    if "\0" in text:
        raise ClipboardReadError("contains NUL")
    return text
