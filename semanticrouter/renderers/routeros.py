"""Render supported common-model features into a concrete RouterOS 7 syntax train."""

import re
from ipaddress import ip_interface

from ..definitions import definition
from .base import UnsupportedExport


def quote(value):
    """Escape a literal RouterOS value, including dollars that would trigger substitution."""
    s = str(value)
    return (
        '"'
        + s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("$", "\\$")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        + '"'
    )


def command(path, **attrs):
    """Create one additive RouterOS statement, omitting only absent semantic values."""
    return (
        path
        + " add "
        + " ".join(k + "=" + quote(v) for k, v in attrs.items() if v is not None)
    )


def render(router, version):
    """Return configuration lines and omissions; never apply output to a device."""
    diagnostics = []
    lines = []

    def issue(message):
        diagnostics.append(message)

    if not re.fullmatch(r"7\.\d+(?:\.\d+)?", version):
        raise UnsupportedExport("Choose a concrete stable RouterOS 7 version.")
    parts = tuple(map(int, version.split(".")))
    d = definition("routeros-7")
    minimum = tuple(map(int, d["export_min_version"].split(".")))
    maximum = tuple(map(int, d["export_max_version_exclusive"].split(".")))
    if not (minimum <= parts < maximum):
        raise UnsupportedExport(d["export_note"])
    if router.identity:
        lines.append("/system identity set name=" + quote(router.identity))
    if router.dns:
        lines.append("/ip dns set servers=" + quote(",".join(router.dns)))
    for a in router.addresses:
        if a.peer and a.peer not in (
            str(ip_interface(a.address).ip),
            str(ip_interface(a.address).network.network_address),
        ):
            issue("Host-route peer addressing is not exported: " + a.interface)
            continue
        lines.append(
            command(
                "/ip address",
                address=a.address,
                interface=a.interface,
                disabled="no" if a.enabled else "yes",
            )
        )
    for g in router.firewall_v4.groups:
        lines.append(
            command(
                "/ip firewall address-list",
                address=g.network,
                list=g.name,
                disabled="no" if g.enabled else "yes",
            )
        )
    for f in router.firewall_v4.rules:
        if f.extra:
            issue("Unsupported firewall predicates at " + str(f.source))
            continue
        if f.action not in ("accept", "drop", "reject", "log", "passthrough"):
            issue("Unsupported firewall action " + f.action)
            continue
        attrs = {
            "chain": f.chain,
            "action": f.action,
            "protocol": f.protocol,
            "src-address": f.source_network,
            "src-address-list": f.source_group,
            "dst-address": f.destination_network,
            "dst-address-list": f.destination_group,
            "dst-port": f.destination_ports,
            "src-port": f.source_ports,
            "in-interface": f.ingress,
            "out-interface": f.egress,
            "disabled": "no" if f.enabled else "yes",
        }
        lines.append(command("/ip firewall filter", **attrs))
    for rule in router.bgp.policies:
        if not rule.supported:
            issue("Unsupported routing policy at " + str(rule.source))
            continue
        action = "reject" if rule.action == "discard" else rule.action
        expr = action + ";"
        if rule.prefix:
            condition = "dst " + ("==" if rule.exact else "in") + " " + rule.prefix
            if rule.min_length == rule.max_length:
                condition += " && dst-len == " + str(rule.min_length)
            else:
                if rule.min_length:
                    condition += " && dst-len >= " + str(rule.min_length)
                if rule.max_length < 32:
                    condition += " && dst-len <= " + str(rule.max_length)
            expr = "if (" + condition + ") { " + action + "; }"
        lines.append(
            command(
                "/routing filter rule",
                chain=rule.chain,
                rule=expr,
                disabled="no" if rule.enabled else "yes",
            )
        )
    for p in router.bgp.peers:
        if not p.remote_address or not p.local_as or not p.role:
            issue("Incomplete BGP peer " + p.name)
            continue
        attrs = {
            "name": p.name,
            "remote.address": p.remote_address,
            "remote.as": p.remote_as,
            "local.address": p.local_address,
            "local.role": p.role,
            "as": p.local_as,
            "router-id": p.router_id,
            "input.filter": p.import_policy,
            "output.filter-chain": p.export_policy,
            "output.redistribute": ",".join(p.redistribute) or None,
            "output.default-originate": p.default_originate,
            "disabled": "no" if p.enabled else "yes",
        }
        lines.append(command("/routing bgp connection", **attrs))
    return lines, diagnostics
