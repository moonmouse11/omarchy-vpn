"""Opt-in real INCY ABI checks; run only in a disposable no-network container.

Set INCY_TEST_LIBRARY to the read-only mounted libincycore.so. No host TUN is needed.
"""

import os
from pathlib import Path

import pytest

from incy.worker import Core

LIBRARY = os.environ.get("INCY_TEST_LIBRARY", "")
pytestmark = pytest.mark.skipif(not LIBRARY, reason="INCY bundled library not mounted")


def test_native_core_starts_and_stops_without_tun():
    core = Core(LIBRARY)
    try:
        core.start({"inbounds": [], "outbounds": [{"protocol": "blackhole"}]})
        assert core.running()
    finally:
        core.stop()
    assert not core.running()


def test_native_core_uses_supplied_fd():
    core = Core(LIBRARY)
    with (
        Path("/dev/null").open("rb") as device,
        pytest.raises(OSError, match="Inappropriate ioctl"),
    ):
        core.start(
            {
                "inbounds": [{"protocol": "tun", "settings": {"name": "incy-test"}}],
                "outbounds": [{"protocol": "blackhole"}],
            },
            tun_fd=device.fileno(),
        )
    assert not core.running()
