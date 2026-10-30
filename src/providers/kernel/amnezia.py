"""AmneziaWG block — re-export from kernel wireguard module."""

from providers.kernel.wireguard import AMNEZIA_DIR, AWG_INSTALL_HINT, AmneziaWGProvider

__all__ = ["AMNEZIA_DIR", "AWG_INSTALL_HINT", "AmneziaWGProvider"]
