"""Browser transport: JSON in, JSON out; the same deterministic Python engine."""

import json
from dataclasses import asdict
from ipaddress import ip_address, ip_network

from semanticrouter.adapters.routeros import RouterOSRouter
from semanticrouter.export import export_router
from semanticrouter.model import Diagnostic
from semanticrouter.policy import audit, input_decision, route_decision
from semanticrouter.rules import run_rules, validate_rules
from semanticrouter.serialization import router_from_dict


def handle(request_json):
    """Dispatch one JSON-only browser request to the actual Python middleware.

    Config import is the only operation that parses raw exports. All other actions
    hydrate typed common objects. Request text is never evaluated as Python code.
    Expected validation failures return a structured error without committing a UI
    model mutation; the browser keeps its previous valid state."""
    try:
        request = json.loads(request_json)
        action = request["action"]
        if action == "rules_validate":
            return json.dumps(
                {"ok": True, "rules": validate_rules(request.get("rules", []))}
            )
        if action == "import":
            router = RouterOSRouter(
                request["name"],
                request["text"],
                path=request["name"] + ".cfg",
                version=request.get("version") or None,
            ).to_common()
            if request.get("redacted"):
                router.diagnostics.append(
                    Diagnostic(
                        "redacted-source",
                        "This source view omits credentials or private records; use an original export for complete conversion.",
                    )
                )
            return json.dumps({"ok": True, "router": router.to_dict()})
        routers = [router_from_dict(value) for value in request["routers"]]
        if action == "audit":
            policy = request["policy"]
            allowed = {
                "devices",
                "snmp_pollers",
                "legacy_snmp_pollers",
                "borders",
                "public_prefixes",
            }
            if not isinstance(policy, dict) or set(policy) - allowed:
                raise ValueError(
                    "Policy must be an object containing only supported policy fields"
                )
            for key, values in policy.items():
                if not isinstance(values, list) or any(
                    not isinstance(value, str) for value in values
                ):
                    raise ValueError("Policy " + key + " must be an array of strings")
                if key in ("snmp_pollers", "legacy_snmp_pollers"):
                    if any(ip_address(value).version != 4 for value in values):
                        raise ValueError("SNMP pollers must be IPv4 addresses")
                if key == "public_prefixes":
                    if any(
                        ip_network(value).version != 4
                        or ip_network(value).prefixlen != 24
                        for value in values
                    ):
                        raise ValueError(
                            "Customer-prefix proof currently supports IPv4 /24 aggregates"
                        )
            findings = (
                [asdict(f) for f in audit(routers, policy)]
                if request.get("include_estate", True)
                else []
            )
            results = run_rules(routers, request.get("rules", []))
            for result in results:
                if result.status in ("fail", "unknown"):
                    findings.append(
                        {
                            "device": result.device,
                            "check": "custom." + result.rule_id,
                            "severity": "UNKNOWN"
                            if result.status == "unknown"
                            else result.severity,
                            "message": result.rule_name + ": " + result.message,
                            "source": asdict(result.source) if result.source else None,
                            "rule_id": result.rule_id,
                        }
                    )
            return json.dumps(
                {
                    "ok": True,
                    "findings": findings,
                    "rule_results": [asdict(result) for result in results],
                }
            )
        selected = next(r for r in routers if r.name == request["selected"])
        if action == "probe":
            if request["kind"] == "firewall":
                result = input_decision(
                    selected,
                    request["source"],
                    request["protocol"],
                    int(request["port"]),
                )
            else:
                result = route_decision(selected, request["chain"], request["prefix"])
            return json.dumps({"ok": True, "verdict": result})
        if action == "export":
            result = export_router(
                selected,
                request["vendor"],
                request["version"],
                request.get("partial", False),
            )
            return json.dumps({"ok": True, **asdict(result)})
        raise ValueError("Unknown operation")
    except (ValueError, KeyError, TypeError, StopIteration) as exc:
        return json.dumps(
            {"ok": False, "error": str(exc) or "Selected router is missing"}
        )
