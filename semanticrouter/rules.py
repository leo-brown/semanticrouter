"""User-authored assertions over semantic routers, expressed as data rather than code.

Rule files deliberately use a small, validated vocabulary. They cannot execute
Python, resolve DNS, connect to devices or mutate a router. Every scoped router
gets an explicit pass/fail/unknown/skip result, including when no object matches.
"""

import re
from dataclasses import dataclass
from ipaddress import ip_address, ip_interface, ip_network

from .evaluation import input_decision, route_decision
from .model import Router, Source


@dataclass
class RuleResult:
    """One rule/node result; path and source support navigation back into the IDE."""

    rule_id: str
    rule_name: str
    device: str
    status: str
    severity: str
    message: str
    observed: object = None
    path: str | None = None
    source: Source | None = None


def validate_rules(rules):
    """Validate complete rule files before accepting edits or running assertions."""
    if not isinstance(rules, list) or len(rules) > 100:
        raise ValueError("Rules must be an array of at most 100 rule files")
    ids = set()
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) - {
            "id",
            "name",
            "description",
            "enabled",
            "severity",
            "scope",
            "assert",
        }:
            raise ValueError("Rule contains unsupported fields")
        identity = rule.get("id", "")
        if (
            not isinstance(identity, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", identity)
            or identity in ids
        ):
            raise ValueError(
                "Each rule needs a unique id (letters, digits, hyphens, underscores; max 64)"
            )
        ids.add(identity)
        if not isinstance(rule.get("name"), str) or not 1 <= len(rule["name"]) <= 200:
            raise ValueError(identity + ": name must contain 1–200 characters")
        if type(rule.get("enabled", True)) is not bool or rule.get(
            "severity", "P1"
        ) not in ("P1", "P2"):
            raise ValueError(
                identity + ": use an enabled boolean and severity P1 or P2"
            )
        scope = rule.get("scope", {})
        if not isinstance(scope, dict) or set(scope) - {"roles", "names"}:
            raise ValueError(identity + ": scope supports roles and names")
        for values in scope.values():
            if (
                not isinstance(values, list)
                or len(values) > 100
                or any(not isinstance(v, str) for v in values)
            ):
                raise ValueError(identity + ": scope values must be arrays of strings")
        assertion = rule.get("assert")
        if not isinstance(assertion, dict):
            raise ValueError(identity + ": missing assert object")
        kind = assertion.get("type")
        allowed = {
            "field": {"type", "path", "operator", "value"},
            "packet": {"type", "source", "protocol", "port", "decision"},
            "peers": {"type", "targets", "reciprocal"},
            "route": {"type", "chain", "prefix", "decision"},
        }
        if kind not in allowed or set(assertion) - allowed[kind]:
            raise ValueError(identity + ": unsupported assertion type or fields")
        if kind == "field":
            path = assertion.get("path", "")
            if (
                not isinstance(path, str)
                or len(path) > 200
                or not re.fullmatch(
                    r"[a-z][a-z0-9_]*(?:\[\])?(?:\.[a-z][a-z0-9_]*(?:\[\])?)*", path
                )
            ):
                raise ValueError(
                    identity + ": use a model path such as bgp.peers[].redistribute"
                )
            if assertion.get("operator") not in (
                "equals",
                "contains",
                "includes_all",
                "exists",
                "count_at_least",
            ):
                raise ValueError(identity + ": unsupported field operator")
            if assertion["operator"] != "exists" and "value" not in assertion:
                raise ValueError(identity + ": field assertion needs a value")
            if assertion["operator"] == "includes_all" and not isinstance(
                assertion["value"], list
            ):
                raise ValueError(identity + ": includes_all needs an array value")
            if assertion["operator"] == "count_at_least" and (
                type(assertion["value"]) is not int or assertion["value"] < 0
            ):
                raise ValueError(
                    identity + ": count_at_least needs a nonnegative integer"
                )
        elif kind == "packet":
            if ip_address(assertion.get("source", "")).version != 4:
                raise ValueError("Packet source must be IPv4")
            if assertion.get("protocol", "udp") not in ("udp", "tcp", "icmp", "ospf"):
                raise ValueError("Packet protocol must be udp, tcp, icmp or ospf")
            if (
                type(assertion.get("port", 161)) is not int
                or not 0 <= assertion.get("port", 161) <= 65535
            ):
                raise ValueError("Packet port must be an integer between 0 and 65535")
            if assertion.get("decision", "accept") not in ("accept", "drop"):
                raise ValueError("Invalid packet decision")
        elif kind == "peers":
            targets = assertion.get("targets")
            if (
                not isinstance(targets, list)
                or not targets
                or len(targets) > 100
                or any(not isinstance(t, str) for t in targets)
            ):
                raise ValueError("Peer assertion needs target router names")
            if type(assertion.get("reciprocal", True)) is not bool:
                raise ValueError("reciprocal must be boolean")
        else:
            if not isinstance(assertion.get("chain"), str) or not assertion["chain"]:
                raise ValueError("Route assertion needs a chain name")
            if ip_network(assertion.get("prefix", ""), strict=False).version != 4:
                raise ValueError("Route prefix must be IPv4")
            if assertion.get("decision", "accept") not in ("accept", "reject"):
                raise ValueError("Invalid route decision")
    return rules


def _values(model, path):
    """Resolve dotted fields and explicit [] expansion without evaluating expressions."""
    values = [model]
    for segment in path.split("."):
        expand = segment.endswith("[]")
        key = segment[:-2] if expand else segment
        output = []
        for value in values:
            if not isinstance(value, dict) or key not in value:
                raise ValueError("Model field is unavailable: " + path)
            found = value[key]
            if expand:
                if not isinstance(found, list):
                    raise ValueError("Path is not a collection: " + segment)
                output.extend(found)
            else:
                output.append(found)
        values = output
    return values


def _same(actual, expected):
    """Avoid Python's bool/int equality when comparing JSON assertion values."""
    if isinstance(actual, bool) or isinstance(expected, bool):
        return type(actual) is type(expected) and actual == expected
    if isinstance(actual, list) and isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _same(a, b) for a, b in zip(actual, expected)
        )
    return actual == expected


def _field(router, assertion):
    values = _values(router.to_dict(), assertion["path"])
    if not values:
        return "fail", "No objects match " + assertion["path"], []
    operator = assertion["operator"]
    expected = assertion.get("value")
    if operator != "exists" and any(value is None for value in values):
        return (
            "unknown",
            "Explicit evidence is missing for " + assertion["path"],
            values,
        )

    def matches(value):
        if operator == "exists":
            return value is not None
        if operator == "equals":
            return _same(value, expected)
        if not isinstance(value, list):
            raise ValueError(operator + " requires a collection value")
        if operator == "contains":
            return any(_same(item, expected) for item in value)
        if operator == "includes_all":
            return all(
                any(_same(item, wanted) for item in value) for wanted in expected
            )
        return len(value) >= expected

    passed = all(matches(value) for value in values)
    return (
        ("pass" if passed else "fail"),
        (
            "Expectation satisfied"
            if passed
            else "Expected " + operator + " " + json_value(expected)
        ),
        values,
    )


def json_value(value):
    """Keep result summaries bounded; the complete values remain available separately."""
    import json

    text = json.dumps(value, ensure_ascii=False)
    return text if len(text) < 180 else text[:177] + "…"


def _peers(router, assertion, inventory):
    observations = []
    for target in assertion["targets"]:
        if target not in inventory:
            return "unknown", "Target router is not loaded: " + target, observations
        other = inventory[target]
        addresses = {
            str(ip_interface(a.address).ip) for a in other.addresses if a.enabled
        }
        peers = [
            p
            for p in router.bgp.peers
            if p.enabled and (p.remote_address or "").split("/")[0] in addresses
        ]
        matched = bool(peers)
        if assertion.get("reciprocal", True):
            matched = any(
                p.local_address
                and any(
                    q.enabled
                    and (q.remote_address or "").split("/")[0]
                    == p.local_address.split("/")[0]
                    and (q.local_address or "").split("/")[0]
                    == (p.remote_address or "").split("/")[0]
                    for q in other.bgp.peers
                )
                for p in peers
            )
        observations.append({"target": target, "matched": matched})
    failed = [o["target"] for o in observations if not o["matched"]]
    return (
        ("fail" if failed else "pass"),
        (
            "Missing matching enabled peering: " + ", ".join(failed)
            if failed
            else "Required peerings are configured"
        ),
        observations,
    )


def run_rules(routers: list[Router], rules: list[dict]) -> list[RuleResult]:
    """Evaluate each saved assertion against each scoped router, with explicit skips."""
    validate_rules(rules)
    inventory = {r.name: r for r in routers}
    results = []
    for rule in rules:
        scope = rule.get("scope", {})
        for router in routers:
            selected = (not scope.get("roles") or router.role in scope["roles"]) and (
                not scope.get("names") or router.name in scope["names"]
            )
            if not rule.get("enabled", True) or not selected:
                status, message, observed = (
                    "skip",
                    (
                        "Rule is disabled"
                        if not rule.get("enabled", True)
                        else "Outside rule scope"
                    ),
                    None,
                )
            else:
                assertion = rule["assert"]
                kind = assertion["type"]
                try:
                    if kind == "field":
                        status, message, observed = _field(router, assertion)
                    elif kind == "peers":
                        status, message, observed = _peers(router, assertion, inventory)
                    else:
                        if kind == "packet":
                            observed = input_decision(
                                router,
                                assertion["source"],
                                assertion.get("protocol", "udp"),
                                assertion.get("port", 161),
                            )
                        else:
                            observed = route_decision(
                                router, assertion["chain"], assertion["prefix"]
                            )
                        expected = assertion.get("decision", "accept")
                        status = (
                            "unknown"
                            if observed == "unknown"
                            else ("pass" if observed == expected else "fail")
                        )
                        message = "Expected " + expected + "; observed " + observed
                except (ValueError, TypeError) as error:
                    status, message, observed = "unknown", str(error), None
            results.append(
                RuleResult(
                    rule["id"],
                    rule["name"],
                    router.name,
                    status,
                    rule.get("severity", "P1"),
                    message,
                    observed,
                    rule["assert"].get("path"),
                )
            )
    return results
