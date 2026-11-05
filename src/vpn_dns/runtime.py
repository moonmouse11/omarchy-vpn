"""Fixed root profile storage. User supplies only kind, name and a validated IPv4 map."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

from vpn_dns import profiles as dnsprofiles

DIRECTORIES = {
    "wg": Path("/etc/wireguard"),
    "awg": Path("/etc/amnezia/amneziawg"),
    "ovpn": Path("/etc/openvpn/client"),
}
RUNTIME = Path("/run/omarchy-vpn-profiles")
MAX_CONFIG = 1048576


def _paths(kind: str, name: str) -> tuple[Path, Path]:
    if kind not in DIRECTORIES or re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.=+-]{0,63}", name) is None:
        raise ValueError("Invalid profile identity")
    if kind != "ovpn" and len(name) > 15:
        raise ValueError("WireGuard names are at most 15 characters")
    source = DIRECTORIES[kind] / f"{name}.conf"
    directory = RUNTIME / f"{kind}-{name}"
    if kind == "ovpn" and (
        (_has_runtime(directory) and (directory / f"{name}.ovpn").exists())
        or (not source.exists() and not (directory / source.name).exists())
    ):
        source = DIRECTORIES[kind] / f"{name}.ovpn"
    return source, directory


def _safe_dir(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise PermissionError("Runtime profile directory must be private and root-owned")


def _read(path: Path) -> tuple[str, os.stat_result]:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise PermissionError("Profile must be root-owned and not writable by other users")
        text = stream.read(MAX_CONFIG + 1)
    if len(text) > MAX_CONFIG:
        raise ValueError("Profile is larger than 1 MiB")
    return text, info


def _atomic_text(path: Path, text: str, preserve: os.stat_result | None = None) -> None:
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".profile-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            if preserve is not None:
                os.fchown(stream.fileno(), preserve.st_uid, preserve.st_gid)
                os.fchmod(stream.fileno(), stat.S_IMODE(preserve.st_mode))
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary).replace(path)
    except BaseException:
        with contextlib.suppress(OSError):
            Path(temporary).unlink()
        raise


def describe(kind: str, name: str) -> dict[str, object]:
    source, _ = _paths(kind, name)
    text, _ = _read(source)
    return dnsprofiles.describe(kind, text)


def prepare(
    kind: str, name: str, mapping: dict[str, str], *, expected_ips: list[str] | None = None
) -> Path:
    source, directory = _paths(kind, name)
    original, _ = _read(source)
    numeric = dnsprofiles.numeric_config(kind, original, mapping)
    if expected_ips is not None:
        if not isinstance(expected_ips, list) or any(
            not isinstance(ip, str) for ip in expected_ips
        ):
            raise ValueError("Invalid snapshot IPv4 addresses")
        if dnsprofiles.describe(kind, numeric)["ipv4"] != sorted(set(expected_ips)):
            raise ValueError("Profile endpoints changed since bootstrap; retry connection")
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    _safe_dir(RUNTIME)
    directory.mkdir(mode=0o700)  # Never replace an active/recoverable session.
    try:
        _atomic_text(directory / ".source", original)
        _atomic_text(directory / source.name, numeric)
    except BaseException:
        for path in (directory / ".source", directory / source.name):
            with contextlib.suppress(OSError):
                path.unlink()
        with contextlib.suppress(OSError):
            directory.rmdir()
        raise
    return directory / source.name


def _has_runtime(directory: Path) -> bool:
    try:
        directory.lstat()
    except FileNotFoundError:
        return False
    _safe_dir(RUNTIME)
    _safe_dir(directory)
    return True


def current(kind: str, name: str) -> Path:
    source, directory = _paths(kind, name)
    if not _has_runtime(directory):
        return source
    path = directory / source.name
    _read(path)
    return path


def mark(kind: str, name: str, action: str) -> None:
    _, directory = _paths(kind, name)
    if not _has_runtime(directory):
        return
    if action == "starting":
        _atomic_text(directory / ".starting", "")
    elif action == "started":
        (directory / ".starting").unlink(missing_ok=True)
    elif action == "stopping" and not (directory / ".starting").exists():
        _atomic_text(directory / ".saving", "")


def recover(kind: str, name: str) -> bool:
    _, directory = _paths(kind, name)
    if not _has_runtime(directory):
        return False
    finish(kind, name, save=(directory / ".saving").exists())
    return True


def _retire(directory: Path, filename: str) -> None:
    # Free the profile name atomically; failed cleanup must not block its next connect.
    retired = Path(tempfile.mkdtemp(dir=RUNTIME, prefix=".finished-"))
    try:
        directory.replace(retired)
    except BaseException:
        with contextlib.suppress(OSError):
            retired.rmdir()
        raise
    try:
        for path in (
            retired / filename,
            retired / ".source",
            retired / ".starting",
            retired / ".saving",
        ):
            path.unlink(missing_ok=True)
        retired.rmdir()
    except OSError as error:
        print(
            f"Runtime profile cleanup: retained private recovery data at {retired}: {error}",
            file=sys.stderr,
        )


def finish(kind: str, name: str, *, save: bool) -> None:
    source, directory = _paths(kind, name)
    if not _has_runtime(directory):
        return
    if save and kind in ("wg", "awg") and not (directory / ".starting").exists():
        original, _ = _read(directory / ".source")
        if re.search(r"(?im)^\s*SaveConfig\s*=\s*true\s*(?:#.*)?$", original):
            saved, _ = _read(directory / source.name)
            current_text, info = _read(source)
            restored = dnsprofiles.restore_hostnames(saved, original)
            # A retry may see our completed save, but must never replace newer credentials.
            if current_text not in (original, restored):
                raise ValueError("Source profile changed; private recovery data retained")
            if current_text != restored:
                _atomic_text(source, restored, info)
    # Failed saves retain the private snapshot for recovery instead of losing user state.
    _retire(directory, source.name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fixed root numeric profile operations")
    parser.add_argument(
        "action",
        choices=(
            "describe",
            "prepare",
            "current",
            "finish",
            "discard",
            "starting",
            "started",
            "stopping",
            "recover",
        ),
    )
    parser.add_argument("kind", choices=("wg", "awg", "ovpn"))
    parser.add_argument("name")
    args = parser.parse_args(argv)
    try:
        if args.action == "describe":
            print(json.dumps(describe(args.kind, args.name)))
        elif args.action == "prepare":
            data = sys.stdin.read(MAX_CONFIG + 1)
            if len(data) > MAX_CONFIG:
                raise ValueError("Endpoint map is larger than 1 MiB")
            snapshot = json.loads(data)
            if (
                not isinstance(snapshot, dict)
                or set(snapshot) != {"addresses", "ipv4"}
                or not isinstance(snapshot["ipv4"], list)
            ):
                raise ValueError("Invalid endpoint snapshot")
            print(
                prepare(args.kind, args.name, snapshot["addresses"], expected_ips=snapshot["ipv4"])
            )
        elif args.action == "current":
            print(current(args.kind, args.name))
        elif args.action in ("starting", "started", "stopping"):
            mark(args.kind, args.name, args.action)
        elif args.action == "recover":
            if recover(args.kind, args.name):
                print("recovered")
        else:
            finish(args.kind, args.name, save=args.action == "finish")
        return 0
    except (OSError, ValueError) as error:
        print(f"Runtime profile: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
