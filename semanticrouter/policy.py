"""Apply estate intent to common router objects and return actionable findings.

Policy checks consume only semantic objects. Packet/route evaluation is kept in
evaluation.py; source config parsing and firmware syntax never run during an audit."""

from dataclasses import asdict, dataclass

from .evaluation import (
    default_only,
    in_group,
    input_decision,
    network_contains,
    port_contains,
    route_decision,
)
from .model import Source

__all__ = [
    "Finding",
    "audit",
    "audit_brighton",
    "network_contains",
    "in_group",
    "port_contains",
    "input_decision",
    "route_decision",
    "default_only",
]


@dataclass
class Finding:
    """One configuration assertion failure or unresolved result with optional evidence.

    P1 is a high-priority failure, P2 requests review, and UNKNOWN is explicitly not
    a pass. Check identifiers are stable machine-readable keys used by both UIs."""

    device: str
    check: str
    severity: str
    message: str
    source: Source | None = None

    def to_dict(self):
        """Return a JSON-compatible finding with nested source evidence."""
        return asdict(self)


def audit(routers, rules=None, variables=None):
    """Run only the supplied editable rule definitions; empty intent means no checks."""
    from .rules import run_rules

    return [
        Finding(
            result.device,
            result.rule_id,
            "UNKNOWN" if result.status == "unknown" else result.severity,
            result.rule_name + ": " + result.message,
            result.source,
        )
        for result in run_rules(routers, rules or [], variables)
        if result.status in {"fail", "unknown"}
    ]


def audit_brighton(routers, policy):
    """Explicit compatibility helper for the optional editable Brighton example.

    New callers should load a suite, edit its rules, then call audit/run_rules.
    No application invokes this helper as a hidden second check path.
    """
    from .suites import example_suites

    rules = next(s for s in example_suites() if s["id"] == "brighton-example")["rules"]
    for rule in rules:
        for key in rule.get("params", {}):
            if key in policy:
                rule["params"][key] = policy[key]
    return audit(routers, rules)
