from providers.classic import NetworkManagerProvider, OpenVPNProvider
from providers.happd import HappProvider, IncyProvider, KeysProvider
from providers.kernel import AmneziaWGProvider, WireGuardProvider
from providers.vendor.warp import WarpProvider
from providers.vendor.windscribe import WindscribeProvider

ALL_PROVIDERS = [
    WireGuardProvider(),
    AmneziaWGProvider(),
    KeysProvider("vless"),
    KeysProvider("ss"),
    OpenVPNProvider(),
    NetworkManagerProvider(),
    HappProvider(),
    IncyProvider(),
    WarpProvider(),
    WindscribeProvider(),
]
