import json

import pytest

import config
from config import Config, load_config, save_config


def test_defaults_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    cfg = load_config()
    assert cfg.killswitch_mode == "off"
    assert cfg.exit_ip_enabled is True
    assert cfg.exit_ip_max_age == 600
    assert cfg.provider_visible("Anything")


def test_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    cfg = Config(providers={"outline": False}, killswitch_mode="happ")
    save_config(cfg)
    loaded = load_config()
    assert loaded.providers == {"outline": False}
    assert loaded.killswitch_mode == "happ"


def test_invalid_json_ignored(tmp_path, monkeypatch):
    p = tmp_path / "config.json"
    p.write_text("{not json")
    monkeypatch.setattr(config, "CONFIG_PATH", p)
    assert load_config().killswitch_mode == "off"


def test_partial_and_type_safety(tmp_path, monkeypatch):
    p = tmp_path / "config.json"
    p.write_text('{"killswitch_mode": "nonsense", "exit_ip": {"max_age_seconds": 5, "enabled": 0}}')
    monkeypatch.setattr(config, "CONFIG_PATH", p)
    cfg = load_config()
    assert cfg.killswitch_mode == "off"  # invalid value ignored
    assert cfg.exit_ip_max_age == 60  # clamped to minimum
    assert cfg.exit_ip_enabled is False


def test_killswitch_lockdown_roundtrip(tmp_path, monkeypatch):
    from config import Config, load_config, save_config

    p = tmp_path / "config.json"
    monkeypatch.setattr(config, "CONFIG_PATH", p)
    assert load_config().killswitch_lockdown is True  # default: keep blocking

    cfg = Config()
    cfg.killswitch_lockdown = False
    save_config(cfg)
    assert load_config().killswitch_lockdown is False


def test_ip_sources_and_tools_visible_defaults(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    cfg = load_config()
    assert cfg.ip_sources == {}
    assert cfg.tool_visible("anything") is True  # default: visible


def test_ip_sources_roundtrip_with_api_key(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    cfg = Config()
    cfg.ip_sources["abuseipdb"] = {"api_key": "secret-123"}
    cfg.tools_visible["dns_leak_test"] = False
    save_config(cfg)

    loaded = load_config()
    assert loaded.ip_sources["abuseipdb"]["api_key"] == "secret-123"
    assert loaded.tool_visible("dns_leak_test") is False
    assert loaded.tool_visible("ip_info") is True  # untouched key still defaults on


def test_old_config_without_new_keys_still_loads(tmp_path, monkeypatch):
    p = tmp_path / "config.json"
    p.write_text('{"killswitch_mode": "happ"}')
    monkeypatch.setattr(config, "CONFIG_PATH", p)
    cfg = load_config()
    assert cfg.killswitch_mode == "happ"
    assert cfg.ip_sources == {}
    assert cfg.tools_visible == {}


def test_malformed_ip_sources_and_tools_visible_ignored(tmp_path, monkeypatch):
    p = tmp_path / "config.json"
    p.write_text('{"ip_sources": "nope", "tools_visible": ["also nope"]}')
    monkeypatch.setattr(config, "CONFIG_PATH", p)
    cfg = load_config()
    assert cfg.ip_sources == {}
    assert cfg.tools_visible == {}


def test_speed_test_urls_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    save_config(Config(speed_test_urls=["http://10.0.0.5/f.bin", "https://x/y"]))
    assert load_config().speed_test_urls == ["http://10.0.0.5/f.bin", "https://x/y"]


def test_dns_mode_defaults_to_tunnel_and_roundtrips(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    assert load_config().dns_mode == "tunnel"  # leak-proof unless asked otherwise
    save_config(Config(dns_mode="subscription"))
    assert load_config().dns_mode == "subscription"


def test_dns_mode_invalid_value_ignored(tmp_path, monkeypatch):
    p = tmp_path / "config.json"
    p.write_text('{"dns_mode": "direct"}')
    monkeypatch.setattr(config, "CONFIG_PATH", p)
    assert load_config().dns_mode == "tunnel"


def test_dns_autotest_is_off_by_default_and_roundtrips(tmp_path, monkeypatch):
    """Opt-in: every connect would otherwise send ~30 lookups to bash.ws."""
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    assert load_config().dns_autotest is False
    save_config(Config(dns_autotest=True))
    assert load_config().dns_autotest is True


@pytest.mark.parametrize(("raw", "layout"), [('"sidebar"', "sidebar"), ('"grid"', "tree")])
def test_locations_layout_loads_known_values_only(tmp_path, monkeypatch, raw, layout):
    p = tmp_path / "config.json"
    p.write_text(f'{{"locations_layout": {raw}}}')
    monkeypatch.setattr(config, "CONFIG_PATH", p)
    assert load_config().locations_layout == layout


def test_ipv6_guard_defaults_on_and_round_trips(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    assert load_config().ipv6_guard is True
    save_config(Config(ipv6_guard=False))
    assert load_config().ipv6_guard is False


@pytest.mark.parametrize("invalid", ["false", 0, [], {}])
def test_strict_bool_settings_ignore_non_boolean_values(tmp_path, monkeypatch, invalid):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "killswitch_lockdown": invalid,
                "dns_autotest": invalid,
                "panel_key_hints": invalid,
                "ipv6_guard": invalid,
            }
        )
    )
    monkeypatch.setattr(config, "CONFIG_PATH", path)

    loaded = load_config()

    assert loaded.killswitch_lockdown is True
    assert loaded.dns_autotest is False
    assert loaded.panel_key_hints is True
    assert loaded.ipv6_guard is True


def test_strict_bool_settings_accept_real_booleans(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "killswitch_lockdown": False,
                "dns_autotest": True,
                "panel_key_hints": False,
                "ipv6_guard": False,
            }
        )
    )
    monkeypatch.setattr(config, "CONFIG_PATH", path)

    loaded = load_config()

    assert loaded.killswitch_lockdown is False
    assert loaded.dns_autotest is True
    assert loaded.panel_key_hints is False
    assert loaded.ipv6_guard is False


def test_boolean_maps_omit_invalid_values(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "providers": {"openvpn": "false", "windscribe": False, "warp": 1},
                "tools_visible": {"dns_leak_test": "false", "ip_info": True, "speed": 0},
            }
        )
    )
    monkeypatch.setattr(config, "CONFIG_PATH", path)

    loaded = load_config()

    assert loaded.providers == {"windscribe": False}
    assert loaded.tools_visible == {"ip_info": True}


def test_windscribe_preferences_default_for_old_config(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    path.write_text('{"killswitch_mode": "happ"}')
    monkeypatch.setattr(config, "CONFIG_PATH", path)

    loaded = load_config()

    assert loaded.windscribe_protocol == "automatic"
    assert loaded.windscribe_port == ""


def test_windscribe_preferences_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")

    save_config(Config(windscribe_protocol="stealth", windscribe_port="443"))

    loaded = load_config()
    assert (loaded.windscribe_protocol, loaded.windscribe_port) == ("stealth", "443")


def test_windscribe_port_is_canonicalized(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")

    save_config(Config(windscribe_protocol="udp", windscribe_port="0443"))

    assert load_config().windscribe_port == "443"


@pytest.mark.parametrize(
    ("windscribe", "expected"),
    [
        ({"protocol": "bogus", "port": "443"}, ("automatic", "")),
        ({"protocol": "udp", "port": "0"}, ("udp", "")),
        ({"protocol": "udp", "port": "65536"}, ("udp", "")),
        ({"protocol": "udp", "port": 443}, ("udp", "")),
        ({"protocol": "udp", "port": "٤٤٣"}, ("udp", "")),
        ("not an object", ("automatic", "")),
    ],
)
def test_windscribe_preferences_reject_invalid_values(tmp_path, monkeypatch, windscribe, expected):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"windscribe": windscribe}))
    monkeypatch.setattr(config, "CONFIG_PATH", path)

    loaded = load_config()

    assert (loaded.windscribe_protocol, loaded.windscribe_port) == expected
