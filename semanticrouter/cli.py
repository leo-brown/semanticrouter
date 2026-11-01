"""Command-line boundary for inspection, deterministic auditing and explicit export.

Only this module reads user-supplied CLI paths and writes requested artifacts.
The core evaluator/renderers remain usable independently by applications and tests.
"""

import argparse
import json
import sys
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from .adapters.routeros import load
from .export import export_router
from .policy import audit_brighton
from .rules import run_rules
from .suites import validate_suite


def main(argv=None):
    """Dispatch inspection, estate auditing or explicit target rendering.

    Exit 1 denotes P1 audit findings. Exit 2 denotes invalid input, unknown evidence,
    unsupported conversion or an explicitly requested partial export. Diagnostics go
    to stderr so exported configuration on stdout remains a usable artifact."""
    p = argparse.ArgumentParser(prog="semanticrouter")
    sub = p.add_subparsers(dest="command", required=True)
    i = sub.add_parser("inspect")
    i.add_argument("config")
    i.add_argument("--source-version")
    a = sub.add_parser("audit")
    a.add_argument("directory")
    selection = a.add_mutually_exclusive_group(required=True)
    selection.add_argument(
        "--rules", help="Editable suite JSON; all executed checks come from this file"
    )
    selection.add_argument(
        "--policy",
        help="Compatibility: explicitly select the editable Brighton example with parameter overrides",
    )
    a.add_argument("--output")
    a.add_argument("--json", action="store_true")
    e = sub.add_parser("export")
    e.add_argument("config")
    e.add_argument("--vendor", required=True, choices=["routeros", "cisco-ios"])
    e.add_argument("--version", required=True)
    e.add_argument("--source-version")
    e.add_argument("--allow-partial", action="store_true")
    e.add_argument("--output")
    args = p.parse_args(argv)
    try:
        if args.command == "inspect":
            print(
                json.dumps(load(args.config, args.source_version).to_dict(), indent=2)
            )
            return 0
        if args.command == "export":
            result = export_router(
                load(args.config, args.source_version),
                args.vendor,
                args.version,
                args.allow_partial,
            )
            if args.output:
                Path(args.output).write_text(result.text)
            else:
                print(result.text, end="")
            for d in result.diagnostics:
                print(d, file=sys.stderr)
            return 0 if result.complete else 2
        if args.rules:
            suite = validate_suite(json.loads(Path(args.rules).read_text()))
            root = Path(args.directory)
            paths = (
                [root / (name + ".cfg") for name in suite["devices"]]
                if suite.get("devices")
                else sorted([*root.glob("*.cfg"), *root.glob("*.rsc")])
            )
            paths = [path for path in paths if not path.name.startswith(".")]
            if not paths:
                raise ValueError("No .cfg or .rsc exports found")
            routers = [load(path) for path in paths]
            if len({router.name for router in routers}) != len(routers):
                raise ValueError("Config filenames must produce unique router names")
            results = run_rules(routers, suite["rules"], suite.get("variables", {}))
            from .policy import Finding

            findings = [
                Finding(
                    result.device,
                    result.rule_id,
                    "UNKNOWN" if result.status == "unknown" else result.severity,
                    result.rule_name + ": " + result.message,
                )
                for result in results
                if result.status in {"fail", "unknown"}
            ]
        else:
            policy = json.loads(Path(args.policy).read_text())
            routers = [
                load(Path(args.directory) / (name + ".cfg"))
                for name in policy["devices"]
            ]
            findings = audit_brighton(routers, policy)
            results = []
        summary = dict(Counter(f.severity for f in findings))
        report = {
            "kind": "configuration-only",
            "devices": [
                {
                    "name": r.name,
                    "platform": r.to_dict()["platform"],
                    "bgp_peers": len(r.bgp.peers),
                    "firewall_rules": len(r.firewall_v4.rules),
                    "unexported_commands": len(r.unexported),
                    "diagnostics": r.to_dict()["diagnostics"],
                }
                for r in routers
            ],
            "summary": summary,
            "test_summary": dict(Counter(result.status for result in results)),
            "rules": suite["rules"] if args.rules else [],
            "rule_results": [asdict(result) for result in results],
            "findings": [f.to_dict() for f in findings],
        }
        if args.output:
            Path(args.output).write_text(json.dumps(report, indent=2) + "\n")
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(
                f"Loaded {len(routers)} routers. Configuration assertions only. "
                + str(summary)
            )
            for f in findings:
                location = f" ({f.source.path}:{f.source.line})" if f.source else ""
                print(f"{f.severity:7} {f.device:14} {f.check}: {f.message}{location}")
        if args.rules and not any(result.status != "skip" for result in results):
            print(
                "No active tests matched this inventory; configuration has not been validated.",
                file=sys.stderr,
            )
            return 2
        return (
            1
            if any(f.severity == "P1" for f in findings)
            else (2 if any(f.severity == "UNKNOWN" for f in findings) else 0)
        )
    except (OSError, ValueError, KeyError) as exc:
        print(f"semanticrouter: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
