"""Common model. No RouterOS paths or property names in semantic feature fields.

Unknown vendor data lives in provenance and diagnostics, never interpreted as success.
"""
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Source:
    path: str
    line: int


@dataclass
class Diagnostic:
    code: str
    message: str
    source: Source | None = None


@dataclass
class Platform:
    vendor: str = "mikrotik"
    os: str = "routeros"
    version: str | None = None
    family: str | None = None
    hardware: str | None = None
    evidence: list[str] = field(default_factory=list)


@dataclass
class Address:
    address: str
    interface: str
    peer: str | None = None
    enabled: bool = True
    source: Source | None = None


@dataclass
class Interface:
    name: str
    kind: str
    enabled: bool = True
    members: list[str] = field(default_factory=list)
    mode: str | None = None
    parent: str | None = None
    vlan: int | None = None
    comment: str = ""
    source: Source | None = None


@dataclass
class AddressGroup:
    name: str
    network: str
    enabled: bool = True
    source: Source | None = None


@dataclass
class FirewallRule:
    chain: str
    action: str
    protocol: str | None = None
    source_network: str | None = None
    source_group: str | None = None
    destination_network: str | None = None
    destination_group: str | None = None
    destination_ports: str | None = None
    source_ports: str | None = None
    ingress: str | None = None
    egress: str | None = None
    enabled: bool = True
    # Unmodelled matchers must not accidentally become unconditional rules.
    extra: dict[str, str] = field(default_factory=dict)
    source: Source | None = None

    @property
    def unconditional(self):
        return not any((self.protocol, self.source_network, self.source_group,
                        self.destination_network, self.destination_group,
                        self.destination_ports, self.source_ports, self.ingress,
                        self.egress, self.extra))


@dataclass
class FirewallV4:
    rules: list[FirewallRule] = field(default_factory=list)
    groups: list[AddressGroup] = field(default_factory=list)
    connection_tracking: bool | None = None


@dataclass
class BGPPeer:
    name: str
    remote_address: str | None = None
    local_address: str | None = None
    remote_as: str | None = None
    local_as: str | None = None
    router_id: str | None = None
    role: str | None = None
    import_policy: str | None = None
    export_policy: str | None = None
    redistribute: list[str] = field(default_factory=list)
    default_originate: str | None = None
    enabled: bool = True
    source: Source | None = None


@dataclass
class RouteRule:
    chain: str
    action: str
    prefix: str | None = None
    min_length: int = 0
    max_length: int = 32
    exact: bool = False
    enabled: bool = True
    supported: bool = True
    source: Source | None = None


@dataclass
class BGP:
    peers: list[BGPPeer] = field(default_factory=list)
    policies: list[RouteRule] = field(default_factory=list)


@dataclass
class PPPServer:
    interface: str
    mtu: int | None = None
    authentication: list[str] = field(default_factory=list)
    profile: str | None = None
    enabled: bool = True
    source: Source | None = None


@dataclass
class RadiusServer:
    address: str
    source_address: str | None = None
    timeout_ms: int | None = None
    enabled: bool = True
    source: Source | None = None


@dataclass
class Router:
    name: str
    role: str
    identity: str | None = None
    platform: Platform = field(default_factory=Platform)
    firewall_v4: FirewallV4 = field(default_factory=FirewallV4)
    firewall_v6: list[FirewallRule] = field(default_factory=list)
    bgp: BGP = field(default_factory=BGP)
    addresses: list[Address] = field(default_factory=list)
    interfaces: list[Interface] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    snmp_enabled: bool | None = None
    snmp_location: str | None = None
    ppp_servers: list[PPPServer] = field(default_factory=list)
    ppp_local_addresses: dict[str, str] = field(default_factory=dict)
    radius: list[RadiusServer] = field(default_factory=list)
    ospf_interfaces: list[str] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    # Import completeness and export completeness are separate concerns.
    unexported: list[Source] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
