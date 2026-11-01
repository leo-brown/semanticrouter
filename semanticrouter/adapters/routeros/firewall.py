"""Map RouterOS firewall syntax into ordered, vendor-neutral firewall objects.

Unknown matchers stay attached as opaque constraints. Dropping one would broaden
a rule and could turn an uncertain packet decision into an incorrect pass."""

from dataclasses import dataclass

from ...model import AddressGroup, FirewallRule, FirewallV4
from .parser import Command
from .values import enabled


@dataclass
class RouterOSFirewallV4:
    """A vendor feature view over the same ordered parsed command stream."""

    commands: list[Command]

    def to_common(self):
        """Translate explicit IPv4 rules, groups and tracking settings without reordering."""
        f = FirewallV4()
        mapping = {
            "protocol": "protocol",
            "src-address": "source_network",
            "src-address-list": "source_group",
            "dst-address": "destination_network",
            "dst-address-list": "destination_group",
            "dst-port": "destination_ports",
            "src-port": "source_ports",
            "in-interface": "ingress",
            "out-interface": "egress",
        }
        for c in self.commands:
            a = c.attributes
            if c.path == "/ip firewall address-list":
                if a.get("list") and a.get("address"):
                    f.groups.append(
                        AddressGroup(a["list"], a["address"], enabled(a), c.source)
                    )
            elif c.path == "/ip firewall filter":
                f.rules.append(firewall_rule(c, mapping))
            elif c.path == "/ip firewall connection tracking":
                if a.get("enabled") in ("yes", "no"):
                    f.connection_tracking = a["enabled"] == "yes"
        return f


def firewall_rule(c, mapping=None):
    """Translate recognized predicates and preserve every remaining constraint.

    Unresolved selectors and opaque statements receive an extra marker. That marker
    prevents the evaluator from treating a partially understood rule as unconditional."""
    mapping = mapping or {
        "protocol": "protocol",
        "src-address": "source_network",
        "src-address-list": "source_group",
        "dst-address": "destination_network",
        "dst-address-list": "destination_group",
        "dst-port": "destination_ports",
        "src-port": "source_ports",
        "in-interface": "ingress",
        "out-interface": "egress",
    }
    a = c.attributes
    kw = {target: a[k] for k, target in mapping.items() if k in a}
    extra = {
        k: v
        for k, v in a.items()
        if k not in set(mapping) | {"chain", "action", "disabled", "comment"}
    }
    if c.selector or c.opaque:
        extra["_unresolved"] = "yes"
    return FirewallRule(
        a.get("chain", "input"),
        a.get("action", "accept"),
        enabled=enabled(a),
        extra=extra,
        source=c.source,
        **kw,
    )
