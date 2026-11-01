"""Preparing configs must preserve proxy/direct separation without privileged sockopts."""

import copy
import socket
from unittest.mock import Mock

import pytest

from happ.constants import KILLSWITCH_MARK
from incy import network


def test_translates_proxy_mark_but_not_direct_and_preserves_source():
    cfg = {
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "streamSettings": {
                    "sockopt": {
                        "mark": KILLSWITCH_MARK,
                        "interface": "eth0",
                        "tcpFastOpen": True,
                    }
                },
            },
            {
                "tag": "direct",
                "protocol": "freedom",
                "streamSettings": {
                    "sockopt": {
                        "mark": KILLSWITCH_MARK,
                        "customSockopt": [{"level": "1", "opt": "12", "value": "6", "type": "int"}],
                    }
                },
            },
        ]
    }
    original = copy.deepcopy(cfg)
    result = network.prepare_config(cfg)
    assert cfg == original
    proxy, direct = [ob["streamSettings"]["sockopt"] for ob in result["outbounds"]]
    assert "mark" not in proxy and "interface" not in proxy
    assert proxy["tcpFastOpen"] is True
    assert proxy["customSockopt"][-1] == {
        "level": "1",
        "opt": "12",
        "value": "6",
        "type": "int",
    }
    assert direct["customSockopt"][-1] == {
        "level": "1",
        "opt": "12",
        "value": "0",
        "type": "int",
    }


def test_bootstrap_dns_keeps_proxy_permission():
    cfg = {
        "outbounds": [
            {
                "protocol": "freedom",
                "tag": "dns-direct",
                "streamSettings": {"sockopt": {"mark": KILLSWITCH_MARK}},
            }
        ]
    }
    result = network.prepare_config(cfg)
    assert result["outbounds"][0]["streamSettings"]["sockopt"]["customSockopt"][-1]["value"] == "6"


def test_external_tun_does_not_ask_core_to_manage_host_network():
    cfg = {
        "inbounds": [
            {
                "protocol": "tun",
                "settings": {
                    "name": "incy-xray",
                    "mtu": 1500,
                    "gateway": ["172.19.0.2/30"],
                    "autoOutboundsInterface": "auto",
                    "autoSystemRoutingTable": ["0.0.0.0/0"],
                    "autoSystemDnsToGateway": True,
                },
            }
        ]
    }
    result = network.prepare_config(cfg)
    assert result["inbounds"][0]["settings"] == {"name": "incy-xray", "mtu": 1500}


@pytest.mark.parametrize("protocols", [("shadowsocks",), ("vless", "shadowsocks"), ("vless",)])
def test_ss_workaround_only_disables_tun_sniffing(protocols):
    cfg = {
        "inbounds": [
            {"protocol": "tun", "sniffing": {"enabled": True, "routeOnly": True}},
            {"protocol": "http", "sniffing": {"enabled": True}},
        ],
        "outbounds": [{"protocol": protocol} for protocol in protocols],
        "routing": {"rules": [{"domain": ["example.com"], "outboundTag": "direct"}]},
    }
    original = copy.deepcopy(cfg)
    result = network.prepare_config(cfg)
    assert cfg == original
    assert result["inbounds"][0]["sniffing"]["enabled"] is ("shadowsocks" not in protocols)
    assert result["inbounds"][1]["sniffing"]["enabled"] is True
    assert result["routing"] == cfg["routing"]


def test_rejects_malformed_custom_sockopts():
    with pytest.raises(ValueError):
        network.prepare_config(
            {
                "outbounds": [
                    {
                        "streamSettings": {
                            "sockopt": {
                                "customSockopt": "invalid",
                            }
                        }
                    }
                ]
            }
        )


@pytest.mark.parametrize("iface", ["", "a" * 16, "eth0\x00x", "../eth0", "eth0\n"])
def test_privileged_socket_operation_refuses_invalid_interface(iface):
    sock = Mock()
    with pytest.raises(ValueError):
        network.protect_socket(sock, iface)
    sock.setsockopt.assert_not_called()


def test_privileged_socket_operation_sets_only_fixed_mark_and_interface():
    sock = Mock()
    network.protect_socket(sock, "eth0")
    assert sock.setsockopt.call_args_list == [
        ((socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"eth0\0"),),
        ((socket.SOL_SOCKET, socket.SO_MARK, 0x6B74),),
    ]
