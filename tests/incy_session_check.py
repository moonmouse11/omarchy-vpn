"""Opt-in native/root integration. Run ONLY in Dockerfile.incy-test's disposable netns."""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from incy_packets_check import packet_checks

from incy.xray_run import await_ready

ROOT = Path("/inspect")
ENV = {
    **os.environ,
    "PYTHONPATH": "/repo/src",
    "HOME": "/tmp/incy-home",
    "OMARCHY_VPN_INCY_ROOT": str(ROOT),
}
CONFIG = {
    "inbounds": [{"protocol": "tun", "settings": {"name": "incy-xray", "mtu": 1500}}],
    "outbounds": [{"protocol": "blackhole"}],
}


def ip(*args: str) -> None:
    subprocess.run(["ip", *args], check=True, capture_output=True, timeout=5)


def brokers() -> list[int]:
    result = []
    for path in Path("/proc").glob("[0-9]*/cmdline"):
        with contextlib.suppress(OSError):
            if b"/usr/local/bin/omarchy-vpn-incy-network\0" in path.read_bytes():
                result.append(int(path.parent.name))
    return result


def clean() -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if not brokers() and not Path("/sys/class/net/incy-xray").exists():
            routes = subprocess.check_output(["ip", "route"], text=True)
            assert "0.0.0.0/1" not in routes and "128.0.0.0/1" not in routes
            return
        time.sleep(0.05)
    raise AssertionError("INCY left a broker, TUN or route behind")


def start(mode: str, config: dict) -> subprocess.Popen:
    read, write = os.pipe()
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "incy.launcher",
            mode,
            "--ready-fd",
            str(write),
            "--parent-pid",
            str(os.getpid()),
        ],
        user=65534,
        group=65534,
        extra_groups=[],
        pass_fds=(write,),
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=ENV,
    )
    os.close(write)
    try:
        assert proc.stdin is not None
        proc.stdin.write(json.dumps(config).encode())
        proc.stdin.close()
        await_ready(read, 20)
        return proc
    except BaseException:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        proc.wait()
        if proc.stderr:
            print(proc.stderr.read().decode(errors="replace"), file=sys.stderr)
        raise
    finally:
        os.close(read)


def stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
    proc.wait(timeout=12)
    if proc.stderr:
        proc.stderr.close()
    clean()


def lifecycle() -> None:
    for mode in ("probe", "connect"):
        cfg = CONFIG if mode == "connect" else {"outbounds": [{"protocol": "blackhole"}]}
        proc = start(mode, cfg)
        try:
            assert Path("/sys/class/net/incy-xray").exists() == (mode == "connect")
            assert len(brokers()) == 1
        finally:
            stop(proc)
        print(f"Real launcher/helper/native {mode}, clean stop: OK", flush=True)

    for victim in ("broker", "worker"):
        proc = start("connect", CONFIG)
        try:
            os.kill(brokers()[0] if victim == "broker" else proc.pid, signal.SIGKILL)
            proc.wait(timeout=12)
        finally:
            stop(proc)
        print(f"SIGKILL {victim}: no surviving session/TUN/routes: OK", flush=True)

    wrapper = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from incy.xray_run import popen_xray, KEEPER_CFG; "
            f"p=popen_xray({CONFIG!r}, KEEPER_CFG); print(p.pid, flush=True); "
            "import time; time.sleep(60)",
        ],
        user=65534,
        group=65534,
        extra_groups=[],
        env=ENV,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert wrapper.stdout is not None
        worker_pid = int(wrapper.stdout.readline())
        os.kill(wrapper.pid, signal.SIGKILL)
        wrapper.wait(timeout=12)
        clean()
        assert (
            not Path(f"/proc/{worker_pid}/cmdline").exists()
            or not Path(f"/proc/{worker_pid}/cmdline").read_bytes()
        )
        print("SIGKILL keeper owner kills worker and cleans broker/TUN/routes: OK", flush=True)
    finally:
        if wrapper.poll() is None:
            wrapper.kill()
            wrapper.wait()
        if wrapper.stdout:
            wrapper.stdout.close()
        if wrapper.stderr:
            wrapper.stderr.close()


def main() -> None:
    assert os.getuid() == 0
    runtime = Path("/run/user/65534")
    runtime.mkdir(parents=True, mode=0o700)
    os.chown(runtime, 65534, 65534)
    home = Path(ENV["HOME"])
    home.mkdir(mode=0o700)
    os.chown(home, 65534, 65534)
    assets = home / ".local/share/incy/geo_trimmed"
    assets.parent.mkdir(parents=True)
    assets.symlink_to("/opt/xray/assets", target_is_directory=True)
    ip("link", "set", "lo", "up")
    ip("link", "add", "uplink", "type", "dummy")
    ip("link", "set", "uplink", "up")
    ip("address", "add", "198.51.100.2/24", "dev", "uplink")
    ip("route", "add", "default", "dev", "uplink")
    lifecycle()
    packet_checks(start, stop, ip, ENV)
    print("Native session lifecycle and packet checks passed", flush=True)


if __name__ == "__main__":
    main()
