"""Provider visibility and active connection enumeration."""

import config
from providers import ALL_PROVIDERS
from providers.base import VPNConnection

PLUGIN_ID = "omarchy-vpn"  # omarchy-shell plugin id == its IPC target (manifest.json)


def _provider_pool() -> list:
    """Tests patch `vpn_manager.ALL_PROVIDERS`; read that when present."""
    import sys  # noqa: PLC0415 — avoid importing vpn_manager at registry load time

    vm = sys.modules.get("vpn_manager")
    if vm is not None and hasattr(vm, "ALL_PROVIDERS"):
        return vm.ALL_PROVIDERS
    return ALL_PROVIDERS


def visible_providers() -> list:
    """Providers not hidden in the user config."""
    cfg = config.load_config()
    return [p for p in _provider_pool() if cfg.provider_visible(p.name)]


def active_connections(providers=None) -> list[VPNConnection]:
    """What is tunneled right now — every provider by default, hidden ones too."""
    import sys  # noqa: PLC0415

    vm = sys.modules.get("vpn_manager")
    if vm is not None:
        remote = getattr(vm, "active_connections", None)
        if remote is not None and remote is not active_connections:
            if providers is not None:
                return remote(providers=providers)
            return remote()
    pool = providers if providers is not None else _provider_pool()
    out: list[VPNConnection] = []
    for provider in pool:
        if hasattr(provider, "active_connections"):
            # Every real VPNProvider inherits active_connections(); overrides must
            # avoid full connections() on the --status path (default is slow).
            out.extend(provider.active_connections())
        else:
            # Plain test fakes: connections() only.
            out.extend(c for c in provider.connections() if c.active)
    return out
