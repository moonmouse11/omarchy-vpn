"""Start an unprivileged native worker and wait for actual core startup."""

from __future__ import annotations

import contextlib
import json
import os
import select
import subprocess
import sys
from pathlib import Path

KEEPER_CFG = "incy-xray-active.json"
PROBE_CFG = "incy-xray-probe.json"
START_TIMEOUT = 30.0


def await_ready(fd: int, timeout: float) -> None:
    if not select.select([fd], [], [], timeout)[0]:
        raise OSError("INCY worker startup timed out")
    try:
        message = json.loads(os.read(fd, 4096))
    except ValueError:
        raise OSError("INCY worker exited before startup") from None
    if not isinstance(message, dict) or message.get("ready") is not True:
        error = (
            message.get("error", "invalid startup reply") if isinstance(message, dict) else message
        )
        raise OSError(f"INCY worker: {str(error)[:2000]}")


def popen_xray(cfg: dict, slot: str) -> subprocess.Popen[bytes]:
    if slot not in (KEEPER_CFG, PROBE_CFG):
        raise ValueError("bad incy config slot")
    read, write = os.pipe()
    proc: subprocess.Popen[bytes] | None = None
    try:
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "incy.launcher",
                "connect" if slot == KEEPER_CFG else "probe",
                "--ready-fd",
                str(write),
                "--parent-pid",
                str(os.getpid()),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            pass_fds=(write,),
            env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])},
        )
        os.close(write)
        write = -1
        if proc.stdin is None:
            raise OSError("INCY worker stdin unavailable")
        proc.stdin.write(json.dumps(cfg, ensure_ascii=False).encode())
        proc.stdin.close()
        await_ready(read, START_TIMEOUT)
        return proc
    except BaseException:
        if proc is not None:
            with contextlib.suppress(ProcessLookupError):
                proc.terminate()
            if proc.stdin is not None:
                with contextlib.suppress(OSError):
                    proc.stdin.close()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                proc.wait()
        raise
    finally:
        os.close(read)
        if write >= 0:
            os.close(write)
