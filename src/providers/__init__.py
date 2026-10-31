from providers.classic import NetworkManagerProvider, OpenVPNProvider
from providers.happd import HappProvider, IncyProvider, KeysProvider
from providers.kernel import AmneziaWGProvider, WireGuardProvider

ALL_PROVIDERS = [
    WireGuardProvider(),
    AmneziaWGProvider(),
    KeysProvider("vless"),
    KeysProvider("ss"),
    OpenVPNProvider(),
    NetworkManagerProvider(),
    HappProvider(),
    IncyProvider(),
]
