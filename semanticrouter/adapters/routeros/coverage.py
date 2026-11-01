"""Track which imported properties have complete semantic export mappings.

This check is independent of inspection: a router can be useful for auditing while
still carrying commands that prevent a complete conversion. No raw command is
replayed as a shortcut around missing mappings."""

from ipaddress import ip_interface, ip_network

IMPORT_COVERAGE = {
    "/system identity": {"name"},
    "/ip dns": {"servers"},
    "/ip address": {"address", "network", "interface", "disabled"},
    "/ip firewall address-list": {"address", "list", "disabled", "comment"},
    "/ip firewall filter": {
        "chain",
        "action",
        "protocol",
        "src-address",
        "src-address-list",
        "dst-address",
        "dst-address-list",
        "dst-port",
        "src-port",
        "in-interface",
        "out-interface",
        "disabled",
        "comment",
    },
    "/routing filter": {
        "chain",
        "action",
        "prefix",
        "prefix-length",
        "disabled",
        "comment",
    },
    "/routing filter rule": {"chain", "rule", "disabled", "comment"},
    "/routing bgp instance": {"name", "as", "router-id"},
    "/routing bgp peer": {
        "name",
        "remote-address",
        "update-source",
        "remote-as",
        "in-filter",
        "out-filter",
        "instance",
        "disabled",
        "comment",
    },
    "/routing bgp connection": {
        "name",
        "remote.address",
        "local.address",
        "remote.as",
        "as",
        "router-id",
        "local.role",
        "input.filter",
        "output.filter-chain",
        "output.redistribute",
        "output.default-originate",
        "templates",
        "instance",
        "disabled",
        "comment",
    },
    "/routing bgp template": {
        "name",
        "as",
        "router-id",
        "output.redistribute",
        "disabled",
        "templates",
    },
}


def mark_import_coverage(router, commands):
    """Record each command whose complete semantics cannot be exported.

    Inspection success is deliberately independent of conversion coverage. Selectors,
    unsupported properties, interface-based update sources and nonportable peer
    addressing all keep a source reference in ``router.unexported``."""
    router.unexported = []
    for c in commands:
        attrs = c.attributes
        known = IMPORT_COVERAGE.get(c.path, set())
        if c.path == "/routing bgp instance" and router.platform.family == "6":
            known = known | {
                "redistribute-connected",
                "redistribute-static",
                "redistribute-ospf",
                "redistribute-other-bgp",
                "redistribute-rip",
            }
        if c.path == "/routing bgp peer" and attrs.get("update-source"):
            try:
                ip_network(attrs["update-source"], strict=False)
            except ValueError:
                known = set()  # Interface-based update-source needs address resolution.
        if (
            c.path in ("/routing bgp instance", "/routing bgp template")
            and not router.bgp.peers
        ):
            known = (
                set()
            )  # Unused local BGP definitions have no common-model representation.
        if c.path == "/ip address" and attrs.get("network") and attrs.get("address"):
            addr = attrs["address"].split("/")[0]
            conventional = str(ip_interface(attrs["address"]).network.network_address)
            if attrs["network"] not in (addr, conventional):
                known = set()  # Host-route peer semantics not yet portable.
        selector_ok = (
            c.verb == "add"
            or c.path
            in (
                "/system identity",
                "/ip dns",
                "/routing bgp instance",
                "/routing bgp template",
            )
        ) and (
            not c.selector
            or (
                c.path in ("/routing bgp instance", "/routing bgp template")
                and c.selector == "default"
            )
        )
        if (
            c.opaque
            or c.verb not in ("add", "set")
            or not selector_ok
            or c.path not in IMPORT_COVERAGE
            or not set(attrs) <= known
        ):
            router.unexported.append(c.source)
