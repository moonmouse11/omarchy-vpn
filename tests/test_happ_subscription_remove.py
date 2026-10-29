"""Remove a Happ subscription from the plugin (not from the Happ app)."""

import json

import happmeta
import vpn_manager
from providers.base import VPNConnection


def test_forget_subscription_hides_provider_and_drops_cache(monkeypatch, tmp_path):
    log = tmp_path / "sub.log"
    cache_dir = tmp_path / "cache"
    removed_file = tmp_path / "removed.json"
    monkeypatch.setattr(happmeta, "LOG_FILE", log)
    monkeypatch.setattr(happmeta, "SUB_CACHE_DIR", cache_dir)
    monkeypatch.setattr(happmeta, "PROVIDERS_CACHE", cache_dir / "happ-providers.json")
    monkeypatch.setattr(happmeta, "REMOVED_SUBSCRIPTIONS", removed_file)
    log.write_text("Subscription #42 starting update from: https://vpn.example/sub\n")
    cache_dir.mkdir()
    (cache_dir / "subscription-42.json").write_text('{"at": 1, "servers": []}')

    assert "42" in happmeta.providers()
    happmeta.forget_subscription("42")
    assert "42" not in happmeta.providers()
    assert not (cache_dir / "subscription-42.json").exists()
    assert json.loads(removed_file.read_text()) == ["42"]


def test_run_subscription_delete_refuses_active_tunnel(monkeypatch, tmp_path):
    active = VPNConnection(
        name="🇩🇪 DE",
        provider="Happ",
        active=True,
        subscription_id="42",
    )

    class FakeHapp:
        name = "Happ"

        def connections(self):
            return [active]

    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [FakeHapp()])
    monkeypatch.setattr(
        happmeta,
        "forget_subscription",
        lambda sub_id: (_ for _ in ()).throw(AssertionError("must not forget")),
    )
    result = vpn_manager.run_subscription_delete("Happ", "42")
    assert not result.success
    assert "Disconnect" in result.message


def test_run_subscription_delete_forgets_quick_entries(monkeypatch, tmp_path):
    import quickconnect

    log = tmp_path / "sub.log"
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr(happmeta, "LOG_FILE", log)
    monkeypatch.setattr(happmeta, "SUB_CACHE_DIR", cache_dir)
    monkeypatch.setattr(happmeta, "PROVIDERS_CACHE", cache_dir / "happ-providers.json")
    monkeypatch.setattr(happmeta, "REMOVED_SUBSCRIPTIONS", tmp_path / "removed.json")
    monkeypatch.setattr(quickconnect, "QUICK_FILE", tmp_path / "quick.json")
    log.write_text("Subscription #7 starting update from: https://vpn.example/a\n")
    cache_dir.mkdir()

    class FakeHapp:
        name = "Happ"

        def connections(self):
            return []

    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [FakeHapp()])
    quickconnect.remember("Happ", "🇩🇪 DE", "7")
    assert vpn_manager.run_subscription_delete("Happ", "7").success
    assert quickconnect.load()["recent"] == []
