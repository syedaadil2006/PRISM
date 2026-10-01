"""Environment inventory: the asset/identity context the graph is scored against.

Correlation can be done from logs alone, but prediction needs to know which
hosts matter and who is entitled to reach them. That context lives here.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class HostAsset(BaseModel):
    name: str
    ip: str | None = None
    role: str = "workstation"
    #: 0.0 - 1.0 business/security criticality. Domain controllers sit at 1.0.
    criticality: float = 0.3
    #: True for domain controllers, PKI, backup servers, etc.
    is_critical_infrastructure: bool = False
    #: Hosts this host can reach on the network (used for path proximity).
    reachable_hosts: list[str] = Field(default_factory=list)
    os: str | None = None
    zone: str = "corp"
    owner: str | None = None


class UserIdentity(BaseModel):
    name: str
    display_name: str | None = None
    department: str | None = None
    #: 0.0 - 1.0 privilege level. Domain admins sit at 1.0.
    privilege: float = 0.2
    is_privileged: bool = False
    #: Hosts this account is entitled to authenticate to.
    accessible_hosts: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)


class Inventory(BaseModel):
    hosts: list[HostAsset] = Field(default_factory=list)
    users: list[UserIdentity] = Field(default_factory=list)
    #: Domains already seen in this environment; anything else is "newly observed".
    known_domains: list[str] = Field(default_factory=list)

    def host(self, name: str | None) -> HostAsset | None:
        if not name:
            return None
        key = name.upper()
        for host in self.hosts:
            if host.name.upper() == key:
                return host
        return None

    def user(self, name: str | None) -> UserIdentity | None:
        if not name:
            return None
        key = name.lower()
        for user in self.users:
            if user.name.lower() == key:
                return user
        return None

    def host_names(self) -> list[str]:
        return [h.name for h in self.hosts]

    def ip_to_host(self) -> dict[str, str]:
        """Reverse map used by parsers that only see IP addresses."""
        return {h.ip: h.name for h in self.hosts if h.ip}

    def critical_hosts(self) -> list[HostAsset]:
        return [h for h in self.hosts if h.is_critical_infrastructure]
