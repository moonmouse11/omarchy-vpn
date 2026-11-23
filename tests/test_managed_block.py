import subprocess
import sys
from pathlib import Path

import pytest

_REAL_POPEN = subprocess.Popen
SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "omarchy-vpn-managed-block"
START = b"-- >>> omarchy-vpn\n"
END = b"-- <<< omarchy-vpn\n"
BLOCK = START + b"new binding\n" + END


def run_helper(operation: str, path: Path, replacement: bytes = b"") -> subprocess.CompletedProcess:
    args = [sys.executable, str(SCRIPT), operation, str(path)]
    process = _REAL_POPEN(
        args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = process.communicate(replacement)
    return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)


def test_replace_appends_one_block_after_unmanaged_content(tmp_path):
    path = tmp_path / "bindings.lua"
    path.write_bytes(b"existing binding")

    result = run_helper("replace", path, BLOCK)

    assert result.returncode == 0, result.stderr.decode()
    assert path.read_bytes() == b"existing binding\n" + BLOCK


def test_replace_preserves_prefix_suffix_and_mode(tmp_path):
    path = tmp_path / "bindings.lua"
    path.write_bytes(b"before\n" + START + b"old binding\n" + END + b"after\n")
    path.chmod(0o640)

    result = run_helper("replace", path, BLOCK)

    assert result.returncode == 0, result.stderr.decode()
    assert path.read_bytes() == b"before\n" + BLOCK + b"after\n"
    assert path.stat().st_mode & 0o777 == 0o640


def test_replace_updates_symlink_target_without_replacing_symlink(tmp_path):
    target = tmp_path / "dotfiles" / "bindings.lua"
    target.parent.mkdir()
    target.write_bytes(b"before\n" + START + b"old\n" + END + b"after\n")
    path = tmp_path / "bindings.lua"
    path.symlink_to(target)

    result = run_helper("replace", path, BLOCK)

    assert result.returncode == 0, result.stderr.decode()
    assert path.is_symlink()
    assert target.read_bytes() == b"before\n" + BLOCK + b"after\n"


def test_remove_deletes_only_the_complete_block(tmp_path):
    path = tmp_path / "bindings.lua"
    path.write_bytes(b"before\n" + START + b"old binding\n" + END + b"after\n")

    result = run_helper("remove", path)

    assert result.returncode == 0, result.stderr.decode()
    assert path.read_bytes() == b"before\nafter\n"


def test_remove_missing_file_succeeds(tmp_path):
    result = run_helper("remove", tmp_path / "missing.lua")

    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize(
    "content",
    [
        b"before\n" + START + b"unterminated\n",
        b"before\n" + END + b"after\n",
        START + b"one\n" + END + START + b"two\n" + END,
        END + b"reversed\n" + START,
        START + START + b"nested\n" + END + END,
    ],
    ids=["opening-only", "closing-only", "duplicate", "reversed", "nested"],
)
@pytest.mark.parametrize("operation", ["replace", "remove"])
def test_malformed_markers_fail_without_modifying_file(tmp_path, operation, content):
    path = tmp_path / "bindings.lua"
    path.write_bytes(content)

    result = run_helper(operation, path, BLOCK)

    assert result.returncode != 0
    assert path.read_bytes() == content


@pytest.mark.parametrize(
    "replacement",
    [
        b"new binding\n",
        START + b"unterminated\n",
        START + b"one\n" + END + START + b"two\n" + END,
    ],
    ids=["no-markers", "opening-only", "duplicate"],
)
def test_invalid_replacement_fails_without_modifying_file(tmp_path, replacement):
    path = tmp_path / "bindings.lua"
    original = b"existing\n"
    path.write_bytes(original)

    result = run_helper("replace", path, replacement)

    assert result.returncode != 0
    assert path.read_bytes() == original
