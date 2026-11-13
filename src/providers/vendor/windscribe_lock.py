"""Cross-process serialization for the single-instance Windscribe CLI."""

import contextlib
import fcntl
import os
import time
from collections.abc import Iterator
from pathlib import Path

LOCK_FILE = Path.home() / ".cache/vpn-manager/windscribe-cli.lock"
_POLL_INTERVAL = 0.01


class CliBusyError(TimeoutError):
    """Another Windscribe CLI command held the lock past our deadline."""


@contextlib.contextmanager
def cli_lock(timeout: float) -> Iterator[None]:
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(LOCK_FILE, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "a") as lock:
        os.fchmod(lock.fileno(), 0o600)
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise CliBusyError("windscribe-cli is busy") from None
                time.sleep(min(_POLL_INTERVAL, max(0.0, deadline - time.monotonic())))
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
