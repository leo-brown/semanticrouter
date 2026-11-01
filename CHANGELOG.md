# Changelog

## Unreleased

- No implicit network policy: new workspaces start with no active rules.
- Test design promoted to the main workspace, with explicit per-rule Run choices.
- All 29 former estate checks moved into optional, fully editable example suites.
- Bounded JSON expressions support custom logic, parameters and cross-router tests.
- Portable suite import/export and generic CLI `audit --rules`; shared generic
  variables.

- IDE configuration flow with source/model drafts, rule files, test inspection and
  export.
- Reusable declarative field, packet, reciprocal-peer and route-filter assertions.
- Rule builder and JSON authoring, role/name scopes, validated save and browser
  persistence.
- Credential-redacted source views, line navigation, model diffs and workspace restore.
- Inventory uncertainty separated from actionable findings; explicit source mapping
  gaps.

## 0.1.0

- RouterOS 6/7 non-executing export parser and vendor feature adapters.
- Common router, firewall, BGP, addressing, interface and subscriber-service objects.
- Strict semantic JSON hydration with provenance and uncertainty preserved.
- Deterministic management, subscriber-service and BNG/border policy assertions.
- Supported-subset RouterOS 7 rendering and unattached Cisco IOS 15 ACL rendering.
- Self-contained browser playground, with optional authenticated PHP hosting.
- Explicit import/export coverage, partial-fragment diagnostics and regression tests.
- Modular source layout, detailed API/invariant documentation and clean-build checks.
- Conservative handling of negated unresolved networks and numeric IP protocols.
