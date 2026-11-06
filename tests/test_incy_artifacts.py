"""Native test inputs are pinned independently of the user's runtime installation."""

import hashlib
from pathlib import Path

import incy_artifacts
import pytest


@pytest.fixture
def artifacts(monkeypatch, tmp_path):
    root = tmp_path / "incy"
    library = root / "lib/app/resources/bin/libincycore.so"
    library.parent.mkdir(parents=True)
    library.write_bytes(b"synthetic native artifact")
    manifest = tmp_path / "artifacts.sha256"
    digest = hashlib.sha256(library.read_bytes()).hexdigest()
    manifest.write_text(f"# Synthetic test fixture\n{digest}  {library.relative_to(root)}\n")
    monkeypatch.setattr(incy_artifacts, "MANIFEST", manifest)
    return root, library


def test_accepts_exact_artifact(artifacts):
    root, _ = artifacts
    incy_artifacts.verify_artifacts(root)


def test_rejects_tampered_artifact(artifacts):
    root, library = artifacts
    library.write_bytes(b"different core version")
    with pytest.raises(ValueError, match=r"SHA256 mismatch.*libincycore"):
        incy_artifacts.verify_artifacts(root)


def test_rejects_missing_artifact(artifacts):
    root, library = artifacts
    library.unlink()
    with pytest.raises(FileNotFoundError, match="libincycore"):
        incy_artifacts.verify_artifacts(root)


def test_official_manifest_pins_both_libraries():
    manifest = Path(__file__).with_name("incy-artifacts.sha256").read_text()
    records = [line.split() for line in manifest.splitlines() if line and not line.startswith("#")]
    assert {name for _, name in records} == {
        "lib/app/resources/bin/libincycore.so",
        "lib/app/resources/bin/libxray_ffi.so",
    }
    assert all(len(digest) == 64 for digest, _ in records)
