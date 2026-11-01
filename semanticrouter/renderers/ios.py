"""Render supported IPv4 input semantics as an unattached Cisco IOS named ACL."""

import re
from ipaddress import ip_address, ip_network

from .base import UnsupportedExport


def render(router, version):
    """Return configuration lines and omissions; never apply output to a device."""
    diagnostics = []
    lines = []

    def issue(message):
        diagnostics.append(message)

    if not re.fullmatch(r"15(?:\.\d+)*", version):
        raise UnsupportedExport("Only Cisco IOS 15.x ACL artifact export is supported.")
    if router.identity:
        if not re.fullmatch("[A-Za-z0-9_.-]+", router.identity):
            issue("Invalid IOS hostname")
        else:
            lines.append("hostname " + router.identity)
    if router.dns:
        try:
            servers = [str(ip_address(server)) for server in router.dns]
            lines.append("ip name-server " + " ".join(servers))
        except ValueError:
            issue("IOS DNS servers must be IP literals.")
    # No implicit device-wide attachment: RouterOS input has no direct IOS ACL equivalent.
    lines.extend(
        [
            "! IPv4 input ACL artifact; choose control-plane/interface attachment explicitly.",
            "ip access-list extended SEMANTICROUTER-INPUT",
        ]
    )

    def endpoint(network, group):
        """Expand a supported group into ACL endpoints; unresolved or negated groups fail."""
        if group:
            if group.startswith("!"):
                raise UnsupportedExport(
                    "Negated address groups unsupported in IOS ACLs."
                )
            gs = [
                g.network
                for g in router.firewall_v4.groups
                if g.enabled and g.name == group
            ]
            if not gs:
                raise UnsupportedExport("Missing address group " + group)
            return [address(x) for x in gs]
        return [address(network)]

    def address(value):
        """Render one IPv4 network as any, a host, or network plus wildcard mask."""
        if not value:
            return "any"
        net = ip_network(value, strict=False)
        if net.version != 4:
            raise UnsupportedExport("IPv4 ACL requires IPv4 networks")
        if net.prefixlen == 0:
            return "any"
        return (
            "host " + str(net.network_address)
            if net.prefixlen == 32
            else str(net.network_address) + " " + str(net.hostmask)
        )

    for f in router.firewall_v4.rules:
        if f.chain != "input":
            issue("IOS renderer only supports input ACL rules")
            continue
        if not f.enabled:
            continue
        if (f.source_network and f.source_group) or (
            f.destination_network and f.destination_group
        ):
            issue(
                "Combined address and group predicates need intersection support for IOS."
            )
            continue
        if (
            f.extra
            or f.ingress
            or f.egress
            or f.source_ports
            or f.action not in ("accept", "drop")
        ):
            issue("Unsupported IOS firewall rule at " + str(f.source))
            continue
        if f.protocol not in (None, "tcp", "udp", "icmp", "ospf"):
            issue("Unsupported IOS protocol")
            continue
        if f.destination_ports and (
            f.protocol not in ("tcp", "udp") or not f.destination_ports.isdigit()
        ):
            issue("IOS supports one destination port per rule in this renderer")
            continue
        try:
            sources = endpoint(f.source_network, f.source_group)
            destinations = endpoint(f.destination_network, f.destination_group)
        except (UnsupportedExport, ValueError) as exc:
            issue(str(exc))
            continue
        for src in sources:
            for dst in destinations:
                line = (
                    " "
                    + ("permit" if f.action == "accept" else "deny")
                    + " "
                    + (f.protocol or "ip")
                    + " "
                    + src
                    + " "
                    + dst
                )
                if f.destination_ports:
                    line += " eq " + f.destination_ports
                lines.append(line)
    if not any(
        f.enabled
        and f.chain == "input"
        and f.action in ("accept", "drop")
        and f.unconditional
        for f in router.firewall_v4.rules
    ):
        lines.append(
            " permit ip any any"
        )  # Preserve RouterOS input fall-through acceptance.
    lines.append("exit")
    if router.bgp.peers or router.bgp.policies or router.addresses:
        issue("IOS BGP, route policies and interface addressing are not supported yet.")
    return lines, diagnostics
