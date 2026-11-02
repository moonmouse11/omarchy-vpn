"""Real helper + isolated profile module, fake network binaries, no privileges/network."""

import contextlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REAL_RUN = subprocess.run
REAL_POPEN = subprocess.Popen
CONFIG = """[Interface]
PrivateKey = SECRET
DNS = 10.0.0.1
SaveConfig = true

[Peer]
PublicKey = PUB
Endpoint = vpn.example:51820
PersistentKeepalive = 20
"""


@pytest.fixture
def numeric_helper(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", REAL_POPEN)
    configs = tmp_path / "configs"
    configs.mkdir(mode=0o700)
    source = configs / "office.conf"
    source.write_text(CONFIG)
    source.chmod(0o600)
    trusted = tmp_path / "trusted"
    package = trusted / "vpn_dns"
    package.mkdir(parents=True)
    for name in ("__init__", "profiles", "runtime"):
        text = (ROOT / "src/vpn_dns" / f"{name}.py").read_text()
        for original in ("/etc/wireguard", "/etc/amnezia/amneziawg", "/etc/openvpn/client"):
            text = text.replace(original, str(configs))
        text = text.replace("/run/omarchy-vpn-profiles", str(tmp_path / "runtime"))
        (package / f"{name}.py").write_text(text)
    script = tmp_path / "helper"
    text = (ROOT / "scripts/omarchy-vpn-helper").read_text()
    text = text.replace("/usr/local/lib/omarchy-vpn", str(trusted))
    text = text.replace("/usr/bin/python3", sys.executable)
    text = text.replace("/run/omarchy-vpn-profile.lock", str(tmp_path / "lock"))
    text = text.replace('run kill "$pid"', f'run "{tmp_path}/bin/kill" "$pid"')
    script.write_text(text)
    binaries = tmp_path / "bin"
    binaries.mkdir()
    link = tmp_path / "link"
    failure = tmp_path / "fail"
    for name, body in {
        "ip": f'''test -f "{link}" || exit 1
if [ "$1" = -details ]; then
    if [ -f "{tmp_path}/link-type" ]; then cat "{tmp_path}/link-type"; else echo wireguard; fi
fi''',
        "sysctl": f'''if [ "$1" = -n ]; then
    if [ -f "{tmp_path}/ipv6" ]; then cat "{tmp_path}/ipv6"; else echo 0; fi
else
    case "$*" in
    *disable_ipv6=0*) echo 0 > "{tmp_path}/ipv6";;
    *disable_ipv6=1*) echo 1 > "{tmp_path}/ipv6";;
    esac
fi''',
        "openvpn": """while [ "$#" -gt 0 ]; do
case "$1" in
--config) config=$2; shift 2;;
--writepid) pidfile=$2; shift 2;;
*) shift;;
esac
done
grep -q 'remote 192.0.2.1 ' "$config" || exit 40
if grep -q '^remote-random-hostname' "$config"; then exit 41; fi
echo 321 > "$pidfile"
mkdir -p "$PROC_DIR/321"
echo openvpn > "$PROC_DIR/321/comm"
if [ -f "$PROC_DIR/daemon" ]; then
    sleep 30 </dev/null >/dev/null 2>&1 &
    echo $! > "$PROC_DIR/daemon-pid"
fi
""",
        "kill": 'rm "$PROC_DIR/$1/comm"',
        "wg-quick": f'''case "$1" in
up)
    grep -q 'Endpoint = 192.0.2.1:51820' "$2" || exit 40
    test ! -f "{failure}" || exit 23
    if [ -f "{tmp_path}/pause-up" ]; then
        touch "{tmp_path}/up-ready"
        sleep 30
    fi
    touch "{link}"
    ;;
down)
    test -f "{link}" || exit 1
    sed -i 's/:51820/:51821/; s/Keepalive = 20/Keepalive = 25/' "$2"
    rm "{link}"
    ;;
esac''',
    }.items():
        executable = binaries / name
        executable.write_text(f"#!/bin/sh\n{body}\n")
        executable.chmod(0o755)
    (binaries / "awg-quick").symlink_to("wg-quick")

    def run(*args, stdin=""):
        if args[0] == "up-numeric":
            addresses = json.loads(stdin)
            if "addresses" not in addresses:
                stdin = json.dumps(
                    {"addresses": addresses, "ipv4": sorted(set(addresses.values()))}
                )
        return REAL_RUN(
            ["bash", str(script), *args],
            input=stdin,
            text=True,
            capture_output=True,
            env={
                "PATH": f"{binaries}:/usr/bin:/bin",
                "WG_DIR": str(configs),
                "AWG_DIR": str(configs),
                "OVPN_DIR": str(configs),
                "PID_DIR": str(tmp_path / "pids"),
                "PROC_DIR": str(tmp_path / "proc"),
            },
            timeout=15,
        )

    yield run, source, tmp_path, failure
    daemon_pid = tmp_path / "proc/daemon-pid"
    if daemon_pid.exists():
        with contextlib.suppress(ProcessLookupError):
            os.kill(int(daemon_pid.read_text()), signal.SIGTERM)


@pytest.mark.parametrize("kind", ["wg", "awg"])
def test_numeric_up_and_native_saveconfig_preserve_original_settings(numeric_helper, kind):
    run, source, directory, _ = numeric_helper
    result = run("up-numeric", kind, "office", stdin='{"vpn.example":"192.0.2.1"}')
    assert result.returncode == 0, result.stderr
    assert source.read_text() == CONFIG
    runtime = directory / "runtime" / f"{kind}-office" / "office.conf"
    assert "Endpoint = 192.0.2.1:51820" in runtime.read_text()
    result = run("down", kind, "office")
    assert result.returncode == 0, result.stderr
    saved = source.read_text()
    assert "Endpoint = vpn.example:51821" in saved
    assert "PersistentKeepalive = 25" in saved
    assert "DNS = 10.0.0.1" in saved
    assert "PrivateKey = SECRET" in saved
    assert not runtime.parent.exists()


def test_numeric_failure_does_not_save_or_strand_runtime(numeric_helper):
    run, source, directory, failure = numeric_helper
    failure.touch()
    result = run("up-numeric", "wg", "office", stdin='{"vpn.example":"192.0.2.1"}')
    assert result.returncode == 23, result.stderr
    assert source.read_text() == CONFIG
    assert not (directory / "runtime" / "wg-office").exists()
    failure.unlink()
    assert run("up-numeric", "wg", "office", stdin='{"vpn.example":"192.0.2.1"}').returncode == 0


def test_openvpn_numeric_runtime_lives_until_daemon_stops(numeric_helper):
    run, source, directory, _ = numeric_helper
    original = "client\nremote vpn.example 1194\nremote-random-hostname\n<key>\nSECRET\n</key>\n"
    source.write_text(original)
    result = run("up-numeric", "ovpn", "office", stdin='{"vpn.example":"192.0.2.1"}')
    assert result.returncode == 0, result.stderr
    path = directory / "runtime/ovpn-office/office.conf"
    assert "remote 192.0.2.1 1194" in path.read_text()
    assert "remote-random-hostname" not in path.read_text()
    assert source.read_text() == original
    result = run("down", "ovpn", "office")
    assert result.returncode == 0, result.stderr
    assert not path.parent.exists()
    assert not (directory / "proc/321/comm").exists()
    assert source.read_text() == original


def test_openvpn_can_disconnect_when_source_was_removed(numeric_helper):
    run, source, directory, _ = numeric_helper
    source.write_text("client\nremote vpn.example 1194\n")
    assert run("up-numeric", "ovpn", "office", stdin='{"vpn.example":"192.0.2.1"}').returncode == 0
    source.unlink()
    result = run("down", "ovpn", "office")
    assert result.returncode == 0, result.stderr
    assert not (directory / "proc/321/comm").exists()
    assert not (directory / "runtime/ovpn-office").exists()


def test_daemon_cannot_inherit_profile_lock(numeric_helper):
    run, source, directory, _ = numeric_helper
    (directory / "proc").mkdir()
    (directory / "proc/daemon").touch()
    source.write_text("client\nremote vpn.example 1194\n")
    result = run("up-numeric", "ovpn", "office", stdin='{"vpn.example":"192.0.2.1"}')
    assert result.returncode == 0, result.stderr
    result = run("down", "ovpn", "office")
    assert result.returncode == 0, result.stderr


def test_cancelled_native_start_restores_ipv6_guard(numeric_helper):
    _, source, directory, _ = numeric_helper
    (directory / "ipv6").write_text("1\n")
    (directory / "pause-up").touch()
    proc = REAL_POPEN(
        ["bash", str(directory / "helper"), "up-numeric", "wg", "office"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        env={"PATH": f"{directory}/bin:/usr/bin:/bin", "WG_DIR": str(source.parent)},
    )
    try:
        proc.stdin.write(
            json.dumps({"addresses": {"vpn.example": "192.0.2.1"}, "ipv4": ["192.0.2.1"]})
        )
        proc.stdin.close()
        deadline = time.monotonic() + 10
        while not (directory / "up-ready").exists() and proc.poll() is None:
            if time.monotonic() > deadline:
                pytest.fail("native start did not reach cancellation point")
            time.sleep(0.01)
        assert (directory / "ipv6").read_text().strip() == "0"
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=5)
        assert (directory / "ipv6").read_text().strip() == "1"
        assert source.read_text() == CONFIG
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=5)
        proc.stdout.close()
        proc.stderr.close()


def test_interface_named_all_is_not_a_wildcard_authorization(numeric_helper):
    run, source, directory, _ = numeric_helper
    source = source.with_name("all.conf")
    source.write_text(CONFIG)
    (directory / "link").touch()
    (directory / "link-type").write_text("bridge\n")
    binary = directory / "bin/wg"
    binary.write_text('#!/bin/sh\n[ "$1" = show ] && [ "$2" = all ]\n')
    binary.chmod(0o755)
    result = run("up-numeric", "wg", "all", stdin='{"vpn.example":"192.0.2.1"}')
    assert result.returncode != 0
    assert source.read_text() == CONFIG
    assert (directory / "link").exists()


def test_unrelated_interface_is_never_deleted_or_saved(numeric_helper):
    run, source, directory, _ = numeric_helper
    (directory / "link").touch()
    (directory / "link-type").write_text("bridge\n")
    result = run("up-numeric", "wg", "office", stdin='{"vpn.example":"192.0.2.1"}')
    assert result.returncode != 0
    assert source.read_text() == CONFIG
    assert (directory / "link").exists()
    assert not (directory / "runtime/wg-office").exists()


def test_stale_prepare_is_recovered_before_next_start(numeric_helper):
    run, source, directory, _ = numeric_helper
    assert run("up-numeric", "wg", "office", stdin='{"vpn.example":"192.0.2.1"}').returncode == 0
    # Simulate an externally removed interface, not a completed native SaveConfig down.
    (directory / "link").unlink()
    source.write_text(CONFIG + "# external edit\n")
    result = run("up-numeric", "wg", "office", stdin='{"vpn.example":"192.0.2.1"}')
    assert result.returncode == 0, result.stderr
    assert source.read_text().endswith("# external edit\n")
