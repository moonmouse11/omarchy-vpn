from abc import ABC, abstractmethod
from dataclasses import dataclass

type PingTarget = tuple[str, str, int] | tuple[str, str, int, bool]


@dataclass
class VPNConnection:
    name: str
    provider: str
    active: bool
    interface: str | None = None
    config_path: str | None = None
    uuid: str | None = None  # NetworkManager connection UUID
    # Happ: which subscription this server came from. Server names are only
    # unique within one subscription, so (subscription_id, name) is the
    # real identity — two providers commonly both ship a "🇩🇪 Germany".
    subscription_id: str | None = None
    subscription_name: str | None = None

    @property
    def label(self) -> str:
        """'Happ · Provider C: 🇩🇪 Germany', or 'WireGuard: nl' without a subscription."""
        if self.subscription_name:
            return f"{self.provider} · {self.subscription_name}: {self.name}"
        return f"{self.provider}: {self.name}"


@dataclass
class ActionResult:
    success: bool
    message: str


class VPNProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Display name of the provider, e.g. 'WireGuard'"""
        ...

    @abstractmethod
    def connections(self) -> list[VPNConnection]:
        """Return all known connections (active and inactive)"""
        ...

    def active_connections(self) -> list[VPNConnection]:
        """Tunnels up right now — default scans connections(); providers override."""
        return [c for c in self.connections() if c.active]

    @abstractmethod
    def connect(self, connection: VPNConnection) -> ActionResult: ...

    @abstractmethod
    def disconnect(self, connection: VPNConnection) -> ActionResult: ...

    @abstractmethod
    def import_config(self, path: str) -> ActionResult:
        """Import a config file and register it as a new connection"""
        ...

    def ping_targets(self) -> list[PingTarget]:
        """(connection name, host, port[, icmp_only]) for ping measurement."""
        return []

    def toggle_autostart(self, connection: VPNConnection) -> ActionResult:
        return ActionResult(False, f"{self.name}: autostart not supported")

    def delete_config(self, connection: VPNConnection) -> ActionResult:
        return ActionResult(False, f"{self.name}: config delete not supported")
