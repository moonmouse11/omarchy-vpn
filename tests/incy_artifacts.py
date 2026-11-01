"""Verify native test inputs only; never restrict the user's INCY runtime version."""

import hashlib
from pathlib import Path

MANIFEST = Path(__file__).with_name("incy-artifacts.sha256")


def verify_artifacts(root: Path) -> None:
    for line in MANIFEST.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        expected, name = line.split()
        with (root / name).open("rb") as source:
            actual = hashlib.file_digest(source, "sha256").hexdigest()
        if actual != expected:
            raise ValueError(f"INCY test SHA256 mismatch: {name}; see README native test pinning")
