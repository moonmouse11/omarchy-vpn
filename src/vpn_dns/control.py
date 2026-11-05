"""Fixed root-side endpoint DNS sockets; install only as a root-owned isolated module."""

from __future__ import annotations

import argparse
import array
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

from incy.privileged import caller_uid, require_peer_uid, shutdown_on_signal, uplink_interface
from vpn_dns import resolvers as netresolvers

DNS_MARK = 0x6B75
MAX_RESOLVERS = 16
SESSION_TIMEOUT = 10.0


def endpoint(uid: int, token: str) -> Path:
    if not 0 < uid < 2**32 - 1 or re.fullmatch(r"[0-9a-f]{32}", token) is None:
        raise ValueError("Invalid DNS bootstrap session identity")
    return Path(f"/run/user/{uid}/omarchy-vpn/dns-{token}.sock")


def dns_socket(server: str, tcp: bool, uplink: str, uid: int, gid: int) -> socket.socket:
    address = ipaddress.ip_address(server)
    if (
        address.version != 4
        or address.is_loopback
        or address.is_unspecified
        or address.is_multicast
    ):
        raise ValueError("Invalid bootstrap DNS upstream")
    sock = None
    original_uid, original_gid, original_groups = os.geteuid(), os.getegid(), os.getgroups()
    try:
        # Ordinary socket credentials; only binding and marking need root.
        try:
            os.setgroups([])
            os.setegid(gid)
            os.seteuid(uid)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
        finally:
            os.seteuid(original_uid)
            os.setegid(original_gid)
            os.setgroups(original_groups)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, uplink.encode() + b"\0")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, DNS_MARK)
        sock.settimeout(0.5)
        sock.connect((str(address), 53))
        sock.settimeout(None)
        return sock
    except BaseException:
        if sock is not None:
            sock.close()
        raise


def _request(channel: socket.socket, count: int) -> tuple[int, bool] | None:
    data, ancillary, flags, _ = channel.recvmsg(
        2, socket.CMSG_SPACE(4 * array.array("i").itemsize), socket.MSG_CMSG_CLOEXEC
    )
    fds = array.array("i")
    for level, kind, payload in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            fds.frombytes(payload[: len(payload) - len(payload) % fds.itemsize])
    for fd in fds:
        os.close(fd)
    if (
        len(data) != 2
        or data[:1] not in (b"U", b"T")
        or data[1] >= count
        or ancillary
        or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
    ):
        return None
    return data[1], data[:1] == b"T"


def run_session(channel: socket.socket, uid: int, upstreams: list[str], uplink: str) -> None:
    if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET:
        raise ValueError("Invalid DNS bootstrap channel")
    require_peer_uid(channel, uid)
    _, _, gid = struct.unpack("iII", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    deadline = time.monotonic() + SESSION_TIMEOUT
    channel.settimeout(SESSION_TIMEOUT)
    channel.sendall(json.dumps(upstreams, separators=(",", ":")).encode("ascii"))
    while time.monotonic() < deadline:
        channel.settimeout(max(0.001, deadline - time.monotonic()))
        try:
            request = _request(channel, len(upstreams))
            if request is None:
                return
            slot, tcp = request
            try:
                with dns_socket(upstreams[slot], tcp, uplink, uid, gid) as sock:
                    if socket.send_fds(channel, [b"S"], [sock.fileno()]) != 1:
                        return
            except OSError, ValueError:
                channel.sendall(b"E")
        except OSError:
            return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fixed endpoint DNS socket helper")
    parser.add_argument("token")
    args = parser.parse_args(argv)
    try:
        uid = caller_uid()
        address = endpoint(uid, args.token)
        with (
            socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel,
            shutdown_on_signal(channel),
        ):
            channel.settimeout(5)
            channel.connect(str(address))
            require_peer_uid(channel, uid)
            try:
                upstreams = [
                    value
                    for value in netresolvers.bootstrap_resolvers()
                    if ipaddress.ip_address(value).version == 4
                ][:MAX_RESOLVERS]
                if not upstreams:
                    raise OSError("No system IPv4 DNS upstream is available")
                uplink = uplink_interface()
            except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                channel.sendall(json.dumps({"error": str(error)[:80]}).encode())
                raise
            run_session(channel, uid, upstreams, uplink)
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"DNS bootstrap helper: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
