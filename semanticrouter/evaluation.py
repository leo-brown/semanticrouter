"""Evaluate supported firewall and route predicates over semantic objects.

These functions perform no I/O. They preserve uncertainty rather than inventing
DNS results, interface context, connection state or unsupported policy actions."""

from ipaddress import ip_address, ip_network


def network_contains(network, address):
    """Return true/false for a literal network match, or None when it cannot be resolved.

    A leading ! negates a known result. Hostnames are never resolved: an unresolved
    DNS-backed address-list entry must remain unknown, including under negation."""
    try:
        if network.startswith("!"):
            result = network_contains(network[1:], address)
            return None if result is None else not result
        return ip_address(address.split("/")[0]) in ip_network(network, strict=False)
    except ValueError:
        return None


def in_group(router, name, address):
    """Evaluate active group membership with conservative three-valued logic.

    One definite membership proves a positive match. Otherwise an unresolved entry
    keeps membership unknown. A missing or explicitly empty group has no members."""
    negate = name.startswith("!")
    name = name.lstrip("!")
    matches = [
        network_contains(g.network, address)
        for g in router.firewall_v4.groups
        if g.enabled and g.name == name
    ]
    result = True if True in matches else (None if None in matches else False)
    return not result if negate and result is not None else result


def port_contains(spec, port):
    """Match comma-separated single ports and inclusive ranges without service lookup."""
    if not spec:
        return True
    try:
        return any(
            int(p.split("-")[0]) <= port <= int(p.split("-")[-1])
            for p in spec.split(",")
        )
    except ValueError:
        return None


def input_decision(router, source, protocol="udp", port=161):
    """Evaluate ordered input rules and return accept, drop or unknown.

    An unknown predicate forks matching and nonmatching possibilities. A later
    definite terminal action converges them only when every possible verdict agrees.
    Logging is nonterminal; unsupported actions remain uncertain. This model follows
    the imported RouterOS input fall-through behavior and does not simulate conntrack."""
    # Protocol numbers and names describe the same IP protocol, not all TCP traffic.
    number = {"udp": "17", "tcp": "6", "icmp": "1", "ospf": "89"}.get(protocol)
    outcomes = set()
    for rule in router.firewall_v4.rules:
        if not rule.enabled or rule.chain != "input":
            continue
        tests = [
            rule.protocol in (None, protocol, number),
            port_contains(rule.destination_ports, port),
        ]
        if rule.source_network:
            tests.append(network_contains(rule.source_network, source))
        if rule.source_group:
            tests.append(in_group(router, rule.source_group, source))
        if any(x is False for x in tests):
            continue
        uncertain = any(x is None for x in tests) or any(
            (
                rule.ingress,
                rule.egress,
                rule.destination_network,
                rule.destination_group,
                rule.source_ports,
                rule.extra,
            )
        )
        if rule.action in ("accept", "drop", "reject"):
            outcomes.add("drop" if rule.action == "reject" else rule.action)
            if not uncertain:
                return next(iter(outcomes)) if len(outcomes) == 1 else "unknown"
        elif rule.action in ("log", "passthrough"):
            continue
        else:
            outcomes.add("unknown")
    outcomes.add("accept")  # RouterOS input fall-through accepts.
    return next(iter(outcomes)) if len(outcomes) == 1 else "unknown"


def route_decision(router, chain, prefix):
    """Evaluate a supported ordered prefix policy, refusing to step past unknown rules.

    A missing chain is unknown. A recognized chain preserves its source firmware
    fall-through convention: ROS6 accepts, ROS7 rejects. Route-attribute mutations and
    recursive policy control flow are outside this evaluator."""
    route = ip_network(prefix, strict=False)
    rules = [x for x in router.bgp.policies if x.chain == chain and x.enabled]
    if not chain or not rules:
        return "unknown"
    for r in rules:
        if not r.supported:
            return "unknown"
        if r.prefix:
            net = ip_network(r.prefix, strict=False)
            if not (route == net if r.exact else route.subnet_of(net)):
                continue
        if r.min_length <= route.prefixlen <= r.max_length:
            return "reject" if r.action == "discard" else r.action
    return "accept" if router.platform.family == "6" else "reject"


def default_only(router, chain):
    """Conservatively prove that a simple chain accepts only the default route.

    Returns True for a proof, False for a violation and None for an unsupported rule.
    This intentionally errs toward review when it cannot establish the whole chain."""
    rules = [x for x in router.bgp.policies if x.chain == chain and x.enabled]
    if not rules or route_decision(router, chain, "0.0.0.0/0") != "accept":
        return False
    for r in rules:
        if not r.supported:
            return None
        if r.action == "accept" and not (
            r.prefix == "0.0.0.0/0" and (r.exact or r.max_length == 0)
        ):
            return False
        if r.prefix is None and r.action in ("reject", "discard"):
            return True
    return router.platform.family != "6"  # RouterOS 6 chain fall-through accepts.
