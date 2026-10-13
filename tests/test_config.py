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
