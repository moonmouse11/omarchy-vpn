"""The INCY library must never be loaded into a privileged process."""

import ctypes
from unittest.mock import Mock

import pytest

from incy import worker


@pytest.mark.parametrize("uid", [0, 1000])
def test_rejects_root_or_capabilities_before_loading(monkeypatch, uid):
    monkeypatch.setattr(worker.os, "getuid", lambda: uid)
    monkeypatch.setattr(worker.os, "geteuid", lambda: uid)
    status = "CapPrm:\t0000000000000000\nCapEff:\t0000000000002000\nCapAmb:\t0000000000000000\n"
    monkeypatch.setattr(worker, "STATUS", Mock(read_text=lambda: status))
    load = Mock()
    monkeypatch.setattr(worker.ctypes, "CDLL", load)
    with pytest.raises(PermissionError):
        worker.Core("/unused/libincycore.so")
    load.assert_not_called()


def test_rejects_permitted_capabilities(monkeypatch):
    monkeypatch.setattr(worker.os, "getuid", lambda: 1000)
    monkeypatch.setattr(worker.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(worker, "STATUS", Mock(read_text=lambda: "CapPrm:\t0000000000000001\n"))
    with pytest.raises(PermissionError):
        worker.require_unprivileged()


@pytest.fixture
def library(monkeypatch):
    monkeypatch.setattr(worker, "require_unprivileged", lambda: None)
    lib = Mock()
    lib.IncycoreXrayStart.return_value = None
    lib.IncycoreStartXrayWithTunFd.return_value = None
    lib.IncycoreXrayStop.return_value = None
    lib.IncycoreXrayIsRunning.return_value = 0
    monkeypatch.setattr(worker.ctypes, "CDLL", lambda path: lib)
    return lib


def test_tun_start_uses_explicit_fd_and_signatures(library):
    core = worker.Core("/unused/libincycore.so")
    core.start({"inbounds": []}, tun_fd=7)
    library.IncycoreStartXrayWithTunFd.assert_called_once_with(b'{"inbounds":[]}', 7)
    library.IncycoreXrayStart.assert_not_called()
    assert library.IncycoreStartXrayWithTunFd.argtypes == [ctypes.c_char_p, ctypes.c_int]
    assert library.IncycoreStartXrayWithTunFd.restype is ctypes.c_void_p


def test_probe_start_does_not_use_tun_api(library):
    worker.Core("/unused/libincycore.so").start({})
    library.IncycoreXrayStart.assert_called_once_with(b"{}")
    library.IncycoreStartXrayWithTunFd.assert_not_called()


def test_error_string_is_freed(library):
    error = ctypes.create_string_buffer(b"rejected config")
    pointer = ctypes.addressof(error)
    library.IncycoreXrayStart.return_value = pointer
    with pytest.raises(OSError, match="rejected config"):
        worker.Core("/unused/libincycore.so").start({})
    library.IncycoreFreeString.assert_called_once_with(pointer)


def test_protector_denies_when_broker_raises(library):
    core = worker.Core("/unused/libincycore.so")

    def unavailable(_fd):
        raise OSError("broker unavailable")

    core.set_socket_protector(unavailable)
    callback = library.xray_set_protect.call_args.args[0]
    assert callback(7) is False
    core.stop()
    assert not library.xray_set_protect.call_args.args[0]


def test_protector_preserves_broker_result(library):
    core = worker.Core("/unused/libincycore.so")
    core.set_socket_protector(lambda fd: fd == 7)
    callback = library.xray_set_protect.call_args.args[0]
    assert callback(7) is True
    assert callback(8) is False


def test_cannot_replace_protector_on_running_core(library):
    core = worker.Core("/unused/libincycore.so")
    library.IncycoreXrayIsRunning.return_value = 1
    with pytest.raises(RuntimeError):
        core.set_socket_protector(lambda _fd: True)
    library.xray_set_protect.assert_not_called()


def test_stop_calls_core_and_frees_error(library):
    error = ctypes.create_string_buffer(b"stop failed")
    pointer = ctypes.addressof(error)
    library.IncycoreXrayStop.return_value = pointer
    with pytest.raises(OSError, match="stop failed"):
        worker.Core("/unused/libincycore.so").stop()
    library.IncycoreFreeString.assert_called_once_with(pointer)


@pytest.mark.parametrize("fd", [-1, 0, 1, 2])
def test_rejects_invalid_tun_fd_without_falling_back(library, fd):
    with pytest.raises(ValueError, match="TUN fd"):
        worker.Core("/unused/libincycore.so").start({}, tun_fd=fd)
    library.IncycoreStartXrayWithTunFd.assert_not_called()
    library.IncycoreXrayStart.assert_not_called()
