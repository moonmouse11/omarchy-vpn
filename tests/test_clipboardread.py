import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

import clipboardread

_REAL_POPEN = subprocess.Popen


@pytest.fixture(autouse=True)
def _real_popen(monkeypatch):
    monkeypatch.setattr(clipboardread.subprocess, "Popen", _REAL_POPEN)


def command(code: str, *args: str) -> tuple[str, ...]:
    return (sys.executable, "-c", code, *args)


def assert_reaped(pid_file: Path) -> None:
    pid = int(pid_file.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_exact_byte_limit_succeeds():
    text = clipboardread.read_text(8, command=command("import os; os.write(1, b'x' * 8)"))

    assert text == "x" * 8


def test_limit_plus_one_is_rejected_and_child_is_reaped(tmp_path):
    pid_file = tmp_path / "pid"
    code = (
        "import os, pathlib, sys, time; "
        "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
        "os.write(1, b'x' * 9); time.sleep(60)"
    )

    with pytest.raises(clipboardread.ClipboardReadError, match=r"^too large$"):
        clipboardread.read_text(8, timeout=1, command=command(code, str(pid_file)))

    assert_reaped(pid_file)


def test_incremental_infinite_output_is_rejected_and_child_is_reaped(tmp_path):
    pid_file = tmp_path / "pid"
    code = (
        "import os, pathlib, sys, time; "
        "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
        "\nwhile True:\n os.write(1, b'x' * 16)\n time.sleep(0.01)"
    )

    with pytest.raises(clipboardread.ClipboardReadError, match=r"^too large$"):
        clipboardread.read_text(32, timeout=1, command=command(code, str(pid_file)))

    assert_reaped(pid_file)


def test_silent_clipboard_owner_times_out_and_child_is_reaped(tmp_path):
    pid_file = tmp_path / "pid"
    code = (
        "import os, pathlib, sys, time; "
        "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(60)"
    )
    started = time.monotonic()

    with pytest.raises(clipboardread.ClipboardReadError, match=r"^timed out$"):
        clipboardread.read_text(8, timeout=0.1, command=command(code, str(pid_file)))

    assert time.monotonic() - started < 0.5
    assert_reaped(pid_file)


def test_invalid_utf8_is_rejected():
    with pytest.raises(clipboardread.ClipboardReadError, match=r"^not UTF-8$"):
        clipboardread.read_text(8, command=command("import os; os.write(1, b'\\xff')"))


def test_nul_is_rejected():
    with pytest.raises(clipboardread.ClipboardReadError, match=r"^contains NUL$"):
        clipboardread.read_text(8, command=command("import os; os.write(1, b'a\\0b')"))


def test_nonzero_child_exit_is_unavailable():
    with pytest.raises(clipboardread.ClipboardReadError, match=r"^clipboard unavailable$"):
        clipboardread.read_text(8, command=command("raise SystemExit(7)"))


def test_unicode_text_is_returned():
    text = clipboardread.read_text(32, command=command("import os; os.write(1, 'Привет'.encode())"))

    assert text == "Привет"
