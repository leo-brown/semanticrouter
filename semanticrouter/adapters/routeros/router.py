"""Assemble RouterOS feature adapters into one vendor-neutral router snapshot.

Only explicit configuration evidence is mapped. Credentials and subscriber secret
records have no semantic field, and raw text is excluded from dataclass reprs.
The final coverage pass records source references for every unmapped command."""

import re
from dataclasses import dataclass, field
from pathlib import Path

from ...definitions import detect
from ...model import Address, Diagnostic, Interface, PPPServer, RadiusServer, Router
from .bgp import RouterOSBGP
from .coverage import mark_import_coverage
from .firewall import RouterOSFirewallV4, firewall_rule
from .parser import Command, parse
from .values import enabled, milliseconds


@dataclass
class RouterOSRouter:
    """Vendor router snapshot with raw export text kept as a private source artifact.

    Construct once to lex the export; feature views share that already-parsed command
    sequence. The common model contains supported semantics and provenance, not
    a copy of credentials or arbitrary vendor commands."""

    name: str
    text: str = field(repr=False)
    path: str = "<memory>"
    version: str | None = None
    commands: list[Command] = field(init=False, repr=False)

    def __post_init__(self):
        """Parse the export eagerly so lexical errors are reported at the import boundary."""
        self.commands = list(parse(self.text, self.path))

    @property
    def firewall_v4(self):
        """Return the IPv4 feature adapter over the already-parsed statements."""
        return RouterOSFirewallV4(self.commands)

    @property
    def bgp(self):
        """Select the BGP adapter using firmware evidence rather than hardware guesses."""
        p = detect(self.text, [c.path for c in self.commands], self.version)
        return RouterOSBGP(self.commands, p.family)

    def to_common(self):
        """Build a new common snapshot and then assess complete export coverage.

        Settings are derived from explicit recognized statements. Device-dependent
        selectors remain diagnostic; arbitrary edit scripts are not reconstructed. ROS6
        filter chains need explicit terminal behavior before migration because their
        fall-through differs from ROS7."""
        role = re.match(r"[a-z]+", self.name.lower())
        r = Router(self.name, role.group() if role else "unknown")
        r.platform = detect(self.text, [c.path for c in self.commands], self.version)
        if not r.platform.version:
            r.diagnostics.append(
                Diagnostic(
                    "version-unknown",
                    "Exact firmware absent; syntax family is evidence, not an exact version.",
                )
            )
        r.firewall_v4 = self.firewall_v4.to_common()
        bgp = self.bgp
        r.bgp = bgp.to_common()
        r.diagnostics.extend(bgp.diagnostics)
        for c in self.commands:
            a, p = c.attributes, c.path
            if c.opaque or c.verb not in ("add", "set"):
                r.diagnostics.append(
                    Diagnostic(
                        "unresolved-command", "Command was not evaluated.", c.source
                    )
                )
                continue
            if c.selector and p not in (
                "/interface ethernet",
                "/ppp profile",
                "/routing bgp template",
                "/routing bgp instance",
            ):
                r.diagnostics.append(
                    Diagnostic(
                        "unresolved-selector",
                        "Selector requires device defaults/state.",
                        c.source,
                    )
                )
            if p == "/system identity":
                if "name" in a:
                    r.identity = a["name"]
            elif p == "/ip dns":
                if "servers" in a:
                    r.dns = a["servers"].split(",") if a["servers"] else []
            elif p == "/ip address" and "address" in a:
                addr = a["address"]
                if "/" not in addr:
                    addr += "/32"
                r.addresses.append(
                    Address(
                        addr,
                        a.get("interface", ""),
                        a.get("network"),
                        enabled(a),
                        c.source,
                    )
                )
            elif p in (
                "/interface bridge",
                "/interface bonding",
                "/interface vlan",
                "/interface ethernet",
            ):
                if a.get("name"):
                    r.interfaces.append(
                        Interface(
                            a["name"],
                            p.split()[-1],
                            enabled(a),
                            a.get("slaves", "").split(",") if a.get("slaves") else [],
                            a.get("mode"),
                            a.get("interface"),
                            int(a["vlan-id"]) if "vlan-id" in a else None,
                            a.get("comment", ""),
                            c.source,
                        )
                    )
            elif p == "/snmp":
                if "enabled" in a:
                    r.snmp_enabled = a["enabled"] == "yes"
                if "location" in a:
                    r.snmp_location = a["location"]
            elif p == "/ipv6 firewall filter":
                r.firewall_v6.append(firewall_rule(c))
            elif p == "/interface pppoe-server server":
                r.ppp_servers.append(
                    PPPServer(
                        a.get("interface", ""),
                        int(a["max-mtu"]) if "max-mtu" in a else None,
                        a.get("authentication", "").split(","),
                        a.get("default-profile"),
                        enabled(a),
                        c.source,
                    )
                )
            elif p == "/ppp profile" and a.get("local-address"):
                name = a.get("name", c.selector)
                if "find" in name:
                    m = re.search(r"name\s*=\s*([^\s\]]+)", name)
                    name = m[1] if m else name
                r.ppp_local_addresses[name] = a["local-address"]
            elif p == "/radius":
                r.radius.append(
                    RadiusServer(
                        a.get("address", ""),
                        a.get("src-address"),
                        milliseconds(a.get("timeout")),
                        enabled(a),
                        c.source,
                    )
                )
            elif p == "/routing ospf interface-template" and enabled(a):
                r.ospf_interfaces.extend(
                    filter(None, a.get("interfaces", "").split(","))
                )
        mark_import_coverage(r, self.commands)
        if r.platform.family == "6":
            for chain in {p.chain for p in r.bgp.policies}:
                rules = [p for p in r.bgp.policies if p.chain == chain and p.enabled]
                if not any(
                    p.supported
                    and p.prefix is None
                    and p.action in ("accept", "reject", "discard")
                    for p in rules
                ):
                    r.diagnostics.append(
                        Diagnostic(
                            "route-policy-fallthrough",
                            "ROS6 chain requires an explicit terminal action before migration: "
                            + chain,
                        )
                    )
        # Keep the source artifact out of dataclass fields/repr/JSON. Audits still
        # consume only common objects; full same-vendor export can retain syntax
        # and private fields that deliberately do not belong in the semantic model.
        r._routeros_source = self.text
        r._routeros_source_version = self.version
        return r


def load(path, version=None):
    """Read a UTF-8 export and use its filename stem as the inventory name.

    ``version`` is an optional explicit source firmware version. Conflicting version
    evidence is still rejected by the platform detector."""
    p = Path(path)
    return RouterOSRouter(p.stem, p.read_text(), str(p), version).to_common()
