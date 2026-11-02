"""Typed RouterOS interface semantics with stable native source anchors.

Only explicit settings are interpreted. In particular, an omitted bridge setting
is unknown rather than a guessed factory default. Physical port selectors stay in
its source document; changing a port's name must not turn it into a new port.
"""

from ...model import Interface
from .values import enabled


def explicit_list(attributes, key):
    """Distinguish an omitted property from an explicitly empty comma-separated list."""
    if key not in attributes:
        return None
    return attributes[key].split(",") if attributes[key] else []


def interface_from_command(command):
    """Map one exported interface declaration, retaining its original source anchor.

    The native exporter updates this anchored statement and preserves other native
    properties. This is a semantic projection, not an execution of set/find against
    hypothetical hardware or a claim to understand arbitrary RouterOS scripts.
    """
    attrs = command.attributes
    if not attrs.get("name"):
        return None
    kind = command.path.split()[-1]
    return Interface(
        name=attrs["name"],
        kind=kind,
        enabled=enabled(attrs),
        members=attrs["slaves"].split(",") if attrs.get("slaves") else [],
        mode=attrs.get("mode"),
        parent=attrs.get("interface"),
        vlan=int(attrs["vlan-id"]) if "vlan-id" in attrs else None,
        comment=attrs.get("comment", ""),
        source=command.source,
        vlan_filtering={"yes": True, "no": False}.get(attrs.get("vlan-filtering"))
        if kind == "bridge"
        else None,
        advertised_link_modes=explicit_list(attrs, "advertise")
        if kind == "ethernet"
        else None,
    )
