"""Actual TUN handoff and teardown; root in a disposable --network none container only."""

from __future__ import annotations

import array
import fcntl
import json
import os
import select
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from incy import network, privileged
from incy.worker import Core


def check_worker_broker_death(library: str) -> None:
    with privileged.tunnel() as tun_fd:
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with client, server:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "incy.worker",
                    "--library",
                    library,
                    "--tun-fd",
                    str(tun_fd),
                    "--broker-fd",
                    str(client.fileno()),
                ],
                pass_fds=(tun_fd, client.fileno()),
                user=65534,
                group=65534,
                extra_groups=[],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
            )
            client.close()
            try:
                assert process.stdin is not None and process.stdout is not None
                config = {
                    "inbounds": [
                        {
                            "protocol": "tun",
                            "settings": {
                                "name": "incy-xray",
                                "mtu": 1500,
                            },
                        }
                    ],
                    "outbounds": [{"protocol": "blackhole"}],
                }
                process.stdin.write(json.dumps(config).encode())
                process.stdin.close()
                assert select.select([process.stdout], [], [], 5)[0], "worker startup timed out"
                assert b"started" in process.stdout.readline(), "worker did not start core"
                server.close()
                assert process.wait(timeout=5) == 0, "worker failed after broker death"
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
    print("Worker CLI stops native core after broker channel death: OK", flush=True)


def child(library: str, token: str, ready: int, result: int) -> None:
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    address = privileged.endpoint(65534, token)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
        listener.bind(str(address))
        listener.listen()
        os.write(ready, b"1")
        os.close(ready)
        channel, _ = listener.accept()
    with channel:
        channel.settimeout(5)
        message, rights, flags, _ = channel.recvmsg(
            1, socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC
        )
        assert message == b"T" and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
        fds = array.array("i")
        for level, kind, data in rights:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds.frombytes(data)
        assert len(fds) == 1
        fd = fds[0]
        try:
            assert not os.get_inheritable(fd)
            interface = fcntl.ioctl(fd, 0x800454D2, bytes(40))
            assert interface[:16].rstrip(b"\0") == b"incy-xray"
            core = Core(library)
            try:
                core.start(
                    network.prepare_config(
                        {
                            "inbounds": [
                                {
                                    "protocol": "tun",
                                    "settings": {
                                        "name": "incy-xray",
                                        "mtu": 1500,
                                    },
                                }
                            ],
                            "outbounds": [{"protocol": "blackhole"}],
                        }
                    ),
                    tun_fd=fd,
                )
                assert core.running()
                fd = -1  # Successful native start takes ownership of the descriptor.
                channel.close()
                # Keep the TUN FD open: root cleanup must still remove the interface/routes.
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    try:
                        socket.if_nametoindex("incy-xray")
                    except OSError:
                        break
                    time.sleep(0.05)
                else:
                    raise AssertionError("interface survived broker disconnect")
            finally:
                core.stop()
        finally:
            if fd >= 0:
                os.close(fd)
    address.unlink()
    os.write(result, b"1")
    os.close(result)


def main() -> None:
    if not Path("/.dockerenv").is_file() or os.geteuid() != 0:
        raise RuntimeError("Run only as root in a disposable Docker network namespace")
    links = json.loads(subprocess.check_output(["ip", "-j", "link", "show"]))
    if [link["ifname"] for link in links] != ["lo"]:
        raise RuntimeError("Expected --network none with only lo")
    directory = Path("/run/user/65534/omarchy-vpn")
    directory.mkdir(parents=True, mode=0o700)
    os.chown(directory, 65534, 65534)
    token = "a" * 32
    ready_r, ready_w = os.pipe()
    result_r, result_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(ready_r)
        os.close(result_r)
        child(sys.argv[1], token, ready_w, result_w)
        os._exit(0)
    os.close(ready_w)
    os.close(result_w)
    try:
        assert select.select([ready_r], [], [], 5)[0]
        assert os.read(ready_r, 1) == b"1"
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
            channel.connect(str(privileged.endpoint(65534, token)))
            privileged.run_session(channel, "connect", 65534, "lo")
        assert select.select([result_r], [], [], 5)[0]
        assert os.read(result_r, 1) == b"1"
        routes = json.loads(subprocess.check_output(["ip", "-j", "route", "show"]))
        assert not any(route.get("dev") == "incy-xray" for route in routes)
        print("Authenticated TUN FD -> unprivileged core -> disconnect cleanup: OK", flush=True)
        check_worker_broker_death(sys.argv[1])
    finally:
        os.close(ready_r)
        os.close(result_r)
        child_pid, _ = os.waitpid(pid, os.WNOHANG)
        if not child_pid:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


if __name__ == "__main__":
    main()
