"""Bounded, data-only predicates for editable test suites.

The interpreter understands explicit operators, references and collection bindings.
It does not eval Python, import modules, read files or connect to devices. Network
values and role conventions belong to rule parameters, never to this interpreter.
"""

import re
from ipaddress import ip_interface, ip_network

from .evaluation import default_only, input_decision, port_contains, route_decision
from .model import FirewallRule


class Unresolved(ValueError):
    """The model cannot establish this expression's value."""


ARITIES = {
    "concat": 2,
    "eq": 2,
    "ne": 2,
    "in": 2,
    "contains": 2,
    "set_equals": 2,
    "gt": 2,
    "ge": 2,
    "le": 2,
    "starts_with": 2,
    "get": 2,
    "and": None,
    "or": None,
    "not": 1,
    "length": 1,
    "lower": 1,
    "host": 1,
    "prefix_length": 1,
    "within": 2,
    "last": 1,
    "first": 1,
    "values": 1,
    "enumerate": 1,
    "if": 3,
    "unconditional": 1,
    "port_contains": 2,
    "packet": 4,
    "default_only": 2,
    "route_range": 6,
}
BINDINGS = {"all", "any", "filter", "map"}


def validate_expression(node, depth=0, budget=None):
    """Reject executable syntax, unknown operators, malformed bindings and huge trees."""
    budget = budget if budget is not None else [5000]
    budget[0] -= 1
    if depth > 40 or budget[0] < 0:
        raise ValueError("Expression exceeds nesting or node limit")
    if not isinstance(node, dict):
        if isinstance(node, list):
            for item in node:
                validate_expression(item, depth + 1, budget)
        return
    if set(node) == {"ref"}:
        if not isinstance(node["ref"], str) or not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", node["ref"]
        ):
            raise ValueError(
                "Use a dotted reference such as router.dns or params.pollers"
            )
        if any(part.startswith("_") for part in node["ref"].split(".")):
            raise ValueError("Private references are not supported")
        return
    op = node.get("op")
    if not isinstance(op, str):
        raise ValueError("Expression objects must contain ref or op")
    if op in BINDINGS:
        if (
            set(node) != {"op", "items", "as", "test"}
            or not isinstance(node["as"], str)
            or not re.fullmatch(r"[a-z][a-z0-9_]*", node["as"])
        ):
            raise ValueError("Collection operators need items, as and test")
        if node["as"] in {"router", "routers", "params", "vars", "_models", "_budget"}:
            raise ValueError("Collection binding shadows a reserved reference")
        children = [node["items"], node["test"]]
    else:
        if (
            op not in ARITIES
            or set(node) != {"op", "args"}
            or not isinstance(node["args"], list)
        ):
            raise ValueError("Unsupported expression operator or fields")
        expected = ARITIES[op]
        if (expected is not None and len(node["args"]) != expected) or (
            expected is None and not node["args"]
        ):
            raise ValueError("Wrong argument count for " + op)
        children = node["args"]
    for child in children:
        validate_expression(child, depth + 1, budget)


def _equal(left, right):
    """JSON equality preserves bool/number distinctions, including nested values."""
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            _equal(a, b) for a, b in zip(left, right)
        )
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(
            _equal(left[key], right[key]) for key in left
        )
    return (
        type(left) is type(right)
        or type(left) in (int, float)
        and type(right) in (int, float)
    ) and left == right


def _boolean(value):
    if type(value) is not bool:
        raise Unresolved("Expected a boolean predicate")
    return value


def _logical(nodes, context, conjunction):
    """A definite false/true can resolve an AND/OR despite an unknown sibling."""
    unresolved = None
    for node in nodes:
        try:
            value = _boolean(evaluate(node, context))
            if value != conjunction:
                return value
        except Unresolved as error:
            unresolved = error
    if unresolved:
        raise unresolved
    return conjunction


def _collection(value):
    if not isinstance(value, list):
        raise Unresolved("Expected a collection")
    return value


def evaluate(node, context):
    """Evaluate one validated expression using only JSON values and typed models."""
    context["_budget"][0] -= 1
    if context["_budget"][0] < 0:
        raise Unresolved("Expression evaluation limit reached")
    if isinstance(node, list):
        return [evaluate(item, context) for item in node]
    if not isinstance(node, dict):
        return node
    if "ref" in node:
        value = context
        for key in node["ref"].split("."):
            if not isinstance(value, dict) or key not in value:
                raise Unresolved("Missing value: " + node["ref"])
            value = value[key]
        return value
    op = node["op"]
    if op in BINDINGS:
        items = _collection(evaluate(node["items"], context))
        contexts = [{**context, node["as"]: item} for item in items]
        if op in {"all", "any"}:
            unknown = None
            for child in contexts:
                try:
                    value = _boolean(evaluate(node["test"], child))
                    if value == (op == "any"):
                        if op == "all" and len(context["_failures"]) < 3:
                            item = child[node["as"]]
                            if isinstance(item, dict):
                                item = {
                                    key: value
                                    for key, value in item.items()
                                    if key
                                    not in {"source", "diagnostics", "unexported"}
                                }
                            context["_failures"].append(
                                {"binding": node["as"], "value": item}
                            )
                        return value
                except Unresolved as error:
                    unknown = error
            if unknown:
                raise unknown
            return op == "all"
        if op == "map":
            return [evaluate(node["test"], child) for child in contexts]
        return [
            item
            for item, child in zip(items, contexts)
            if _boolean(evaluate(node["test"], child))
        ]
    if op in {"and", "or"}:
        return _logical(node["args"], context, op == "and")
    if op == "if":
        condition = _boolean(evaluate(node["args"][0], context))
        return evaluate(node["args"][1 if condition else 2], context)
    args = [evaluate(arg, context) for arg in node["args"]]
    a = args[0]
    if op == "concat":
        return str(a) + str(args[1])
    if op in {"eq", "ne"}:
        same = _equal(a, args[1])
        return same if op == "eq" else not same
    if op == "not":
        return not _boolean(a)
    if op == "in":
        return any(_equal(a, item) for item in args[1])
    if op == "contains":
        return (
            args[1] in a
            if isinstance(a, str)
            else any(_equal(args[1], item) for item in a)
        )
    if op == "set_equals":
        left, right = _collection(a), _collection(args[1])
        return all(
            any(_equal(item, wanted) for wanted in right) for item in left
        ) and all(any(_equal(item, wanted) for wanted in left) for item in right)
    if op == "gt":
        return a > args[1]
    if op == "ge":
        return a >= args[1]
    if op == "le":
        return a <= args[1]
    if op == "starts_with":
        return str(a or "").startswith(args[1])
    if op == "get":
        if not isinstance(a, dict) or args[1] not in a:
            raise Unresolved("Referenced object is not available: " + str(args[1]))
        return a[args[1]]
    if op == "length":
        return len(a)
    if op == "values":
        return list(a.values())
    if op == "enumerate":
        return [
            {"index": index, "item": item} for index, item in enumerate(_collection(a))
        ]
    if op in {"first", "last"}:
        if not _collection(a):
            raise Unresolved("Collection is empty")
        return a[0 if op == "first" else -1]
    if op == "lower":
        return str(a or "").lower()
    if op == "host":
        return str(ip_interface(a).ip)
    if op == "prefix_length":
        return ip_interface(a).network.prefixlen
    if op == "within":
        return ip_interface(a).ip in ip_network(args[1], strict=False)
    if op == "unconditional":
        return FirewallRule(**a).unconditional
    if op == "port_contains":
        result = port_contains(a, args[1])
    else:
        if not isinstance(a, dict) or a.get("name") not in context["_models"]:
            raise Unresolved("Router model is not loaded")
        router = context["_models"][a["name"]]
        if op == "packet":
            result = input_decision(router, *args[1:])
        elif op == "default_only":
            result = default_only(router, args[1])
        else:
            _, chain, prefix, minimum, maximum, expected = args
            net = ip_network(prefix)
            if (
                type(minimum) is not int
                or type(maximum) is not int
                or not net.prefixlen <= minimum <= maximum <= net.max_prefixlen
            ):
                raise Unresolved("Invalid route prefix-length range")
            count = sum(
                2 ** (length - net.prefixlen) for length in range(minimum, maximum + 1)
            )
            if count > 4096:
                raise Unresolved("Route proof exceeds 4096 prefixes; narrow its range")
            decisions = [
                route_decision(router, chain, str(subnet))
                for length in range(minimum, maximum + 1)
                for subnet in net.subnets(new_prefix=length)
            ]
            if "unknown" in decisions:
                raise Unresolved("Route policy contains unsupported or missing logic")
            return all(decision == expected for decision in decisions)
    if result is None or result == "unknown":
        raise Unresolved("Semantic decision is unknown")
    return result


def test_expression(test, router, routers, params, variables, snapshots=None):
    """Return the same tri-state contract as other authored assertions."""
    failures = []
    try:
        observed = evaluate(
            test,
            {
                "router": (snapshots or {}).get(router.name) or router.to_dict(),
                "routers": snapshots
                or {name: item.to_dict() for name, item in routers.items()},
                "params": params,
                "vars": variables,
                "_models": routers,
                "_budget": [200000],
                "_failures": failures,
            },
        )
        passed = _boolean(observed)
        return (
            "pass" if passed else "fail",
            "Assertion satisfied" if passed else "Assertion is false",
            {"result": observed, "matches": failures} if failures else observed,
        )
    except (ValueError, TypeError, KeyError, IndexError, AttributeError) as error:
        return "unknown", str(error), None
