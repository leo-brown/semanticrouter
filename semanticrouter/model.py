"""Common model. No RouterOS paths or property names in semantic feature fields.

Unknown vendor data lives in provenance and diagnostics, never interpreted as success.
"""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Source:
    """Location of the original export statement, using one-based line numbers.

    Source references are evidence only; they never cause files to be read during
    a semantic audit. Generated browser snapshots strip machine-local path prefixes."""

    path: str
    line: int


@dataclass
class Diagnostic:
    """An import limitation that callers must preserve when interpreting results."""

    code: str
    message: str
    source: Source | None = None


@dataclass
class Platform:
    """Independent firmware and hardware evidence for a source router.

    ``version`` is exact only when explicitly supplied or present in an export
    header. ``family`` may be inferred from syntax; hardware never proves firmware."""

    vendor: str = "mikrotik"
    os: str = "routeros"
    version: str | None = None
    family: str | None = None
    hardware: str | None = None
    evidence: list[str] = field(default_factory=list)


@dataclass
class Address:
    """Configured interface address, optional RouterOS peer/network evidence and state.

    Host-style RouterOS entries are normalized to /32. A distinct peer may describe
    a point-to-point host route whose semantics the target exporter cannot reproduce."""

    address: str
    interface: str
    peer: str | None = None
    enabled: bool = True
    source: Source | None = None


@dataclass
class Interface:
    """Inspection-level interface, aggregation or VLAN configuration.

    Members belong to a bond, parent identifies a VLAN carrier, and ``enabled``
    reflects configuration rather than operational link state."""

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
    """One ordered-independent membership entry in a named firewall source group."""

    name: str
    network: str
    enabled: bool = True
    source: Source | None = None


@dataclass
class FirewallRule:
    """An ordered firewall rule with canonical predicates and opaque constraints.

    ``extra`` retains unmodelled vendor predicates. Their presence must prevent
    unconditional-rule proofs and complete export; discarding them broadens matches."""

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
        """Whether the rule has no explicit match constraints.

        Chain, action and enabled state are evaluated by callers; they do not constrain
        which packets match a rule within its chain."""
        return not any(
            (
                self.protocol,
                self.source_network,
                self.source_group,
                self.destination_network,
                self.destination_group,
                self.destination_ports,
                self.source_ports,
                self.ingress,
                self.egress,
                self.extra,
            )
        )


@dataclass
class FirewallV4:
    """IPv4 rules, address-group membership and explicit connection-tracking state.

    Rule order is semantic. A null tracking value means the export did not explicitly
    establish enabled or disabled state."""

    rules: list[FirewallRule] = field(default_factory=list)
    groups: list[AddressGroup] = field(default_factory=list)
    connection_tracking: bool | None = None


@dataclass
class BGPPeer:
    """Effective peer configuration after vendor-specific inheritance is resolved.

    Addresses and policy names identify configured relationships, not established
    sessions. Redistribution classes retain their semantic names, including VPN routes."""

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
    """Supported prefix/length route-policy predicate and terminal action.

    ``exact`` distinguishes prefix equality from containment. Unsupported vendor
    expressions keep ``supported=False`` so an evaluator cannot manufacture a verdict."""

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
    """Configured BGP peers and ordered routing-policy rules in the common model."""

    peers: list[BGPPeer] = field(default_factory=list)
    policies: list[RouteRule] = field(default_factory=list)


@dataclass
class PPPServer:
    """Subscriber-facing PPPoE settings; MTU is measured in bytes."""

    interface: str
    mtu: int | None = None
    authentication: list[str] = field(default_factory=list)
    profile: str | None = None
    enabled: bool = True
    source: Source | None = None


@dataclass
class RadiusServer:
    """RADIUS endpoint metadata used for inspection, excluding shared secrets.

    Timeouts are normalized to milliseconds. Source identity is an IP address rather
    than an interface name, so it can be compared directly to the router loopback."""

    address: str
    source_address: str | None = None
    timeout_ms: int | None = None
    enabled: bool = True
    source: Source | None = None


@dataclass
class Router:
    """A mutable, vendor-neutral snapshot of explicit router configuration.

    The model is intentionally partial. Diagnostics describe unresolved meaning,
    while ``unexported`` records source commands without complete export mappings.
    Neither list implies a device is reachable or that a conversion can be deployed."""

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
        """Return a JSON-compatible deep copy, preserving order and uncertainty metadata."""
        return asdict(self)
