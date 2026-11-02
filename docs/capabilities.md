# Capabilities and policy semantics

## Import and firmware definitions

`semanticrouter/firmware/` holds separate firmware definitions for RouterOS 6, RouterOS
7, and Cisco IOS 15, plus a hardware-family registry. The definitions carry syntax
markers, BGP field mappings and target capability/version metadata. Add a separate
definition and adapter tests when a firmware train changes semantics. Version-specific
translation logic lives in the adapter, not in the policy tests.

- RouterOS terse and section-based exports, quoted values, backslash continuations,
  selectors and abbreviated property groups (`local.address=... .role=...`).
- Exact firmware comes from the RouterOS export header or `--source-version`.
- Syntax can establish family 6 or 7; it cannot establish an exact release. Conflicting
  evidence is rejected. Header model is stored independently as hardware identity.
- Hardware does **not** establish firmware. In particular, a CRS326/CRS518 export
  without distinguishing syntax remains an unknown software family.
- These estate exports replace the version-bearing header with
  `# <Removed ROS Timestamp>`. Eight routing nodes have RouterOS 7 syntax evidence; four
  switches have insufficient evidence. None yields an exact version.
- Non-executing parser only: this is an export reader, not a RouterOS script engine. It
  cannot evaluate arbitrary scripts, device-dependent selectors or runtime state.
  Commands/properties outside export coverage remain explicitly unexported.
- This release does not reconstruct arbitrary ordered `add/set/remove` edit scripts.
  Supply a device export snapshot. `set` support is for exported settings, BGP defaults,
  interface metadata and named PPP profiles; selector ambiguity is reported.

## Capabilities

| Feature                                                     | RouterOS 6/7 import                       | RouterOS 7.1–7.19 export                                  | Cisco IOS 15 export                       |
| ----------------------------------------------------------- | ----------------------------------------- | --------------------------------------------------------- | ----------------------------------------- |
| Identity, DNS                                               | Yes                                       | Supported fields                                          | Supported fields                          |
| IPv4 input/other filter rules and address groups            | Yes, unknown predicates opaque            | Supported predicates/actions                              | Input ACL artifact, restricted predicates |
| IPv4 addressing                                             | Yes, including host-style loopbacks/peers | Ordinary addresses; host-peer semantics block full export | Not yet                                   |
| BGP peers, inheritance, simple route policies               | Yes                                       | Supported fields and grammar                              | Not yet                                   |
| Interfaces/bonds/VLANs, PPPoE/profiles, RADIUS, SNMP        | Inspection subset                         | Not yet                                                   | Not yet                                   |
| OSPF interface templates                                    | Interface-name inspection                 | Not yet                                                   | Not yet                                   |
| Arbitrary scripts, NAT/raw/mangle, DHCP, MPLS/VPLS, bridges | Preserved as uncovered source references  | Not yet                                                   | Not yet                                   |

The common model mirrors the vendor feature domains, not every vendor property. Omitted
defaults and unmodelled behavior remain a material limitation. A `complete` export means
all imported configuration commands are covered by the supported semantic mapping; it
does not certify a deployable configuration or recreate hidden defaults. The initial
renderers produce configuration additions for a prepared target, not idempotent
reconciliation or an in-place update of an existing router.

## Migration examples

A synthetic RouterOS 6 BGP/firewall fixture demonstrates a complete supported-subset
migration, including instance redistribution and prefix-length filter conversion:

```sh
python3 -m semanticrouter export tests/fixtures/routeros6.rsc --vendor routeros --version 7.19.3 --output /tmp/migrated.rsc
```

RouterOS 7.20+ BGP instance syntax is preserved by source-aware export. Converting
between that layout and the older template/connection layout requires migration
mappings. This limit is stored in the firmware definition. Early RouterOS 6 minor
releases are parsed by syntax family; only the supplied synthetic 6.49-style fixture has
migration regression coverage so far.

Complete source-aware RouterOS export (`--version source`) retains original native
statements, including features outside semantic translation coverage, and compares the
output against both the requested model and the native statement ledger. It needs the
original source; a redacted or model-only snapshot cannot recover private settings. See
[export verification](export.md). Concrete migrations and cross-vendor renderers still
fail if a feature lacks a target mapping. To deliberately request a fragment:

```sh
python3 -m semanticrouter export /path/to/router.cfg --vendor cisco-ios --version 15.2 --allow-partial --output /tmp/input-acl.ios
```

Partial output carries a banner, reports omissions to stderr and exits `2`. IOS output
is a named IPv4 ACL artifact: the operator must choose its interface/control-plane
attachment. RouterOS input has no automatic device-wide IOS ACL equivalent. There is no
IOS importer yet. Never apply a fragment as if it were a full replacement config.

## Optional editable example suites

`semanticrouter/suites/brighton.json` contains the complete editable logic for 29 estate
checks, including all local values. It is optional and never automatically enabled.
`examples/brighton.json` is an inventory/legacy parameter file, not an implicit policy.
The generic `policy.audit(routers, rules, variables)` operates only on supplied rules.
No rules means no findings. These are example intentions, not universal standards.

Implemented checks include:

- Enabled, unconditional terminal IPv4 input drop/reject; rule-order-aware SNMP access
  for each canonical poller, legacy/extra monitoring sources and SNMP location.
- Editable firmware-family policy and recorded exact-version requirement, identity,
  infrastructure loopbacks, DNS, explicit LACP and disabled production-looking uplinks.
- BNG conntrack disabled; PPPoE placement, MTU, authentication and profile; PPP/RADIUS
  source identity, two RADIUS servers and ordered 500ms/2000ms timeouts.
- BNG distribution uplinks and both-border mesh: active address/session matching,
  reciprocal sessions (including `gw-*` names), named transit, OSPF template and
  explicit OSPF input allow on that transit.
- Connected+VPN redistribution and all customer more-specifics in the six /24 blocks.
  Every /25 through /32 is evaluated: 510 routes per aggregate, not a string-presence
  test. Matching reciprocal border input chains are tested too.
- Default-only border-to-BNG export on the actual reciprocal peer's applied policy.

`UNKNOWN` is distinct from pass. Firewall packet evaluation is deliberately limited:
unknown matches fork possible paths and return a definite verdict only when outcomes
agree. Interface-scoped management accepts are permitted by the source-restriction lint;
interface topology and the authorization of management networks are not proved.
Source-restricted accepts are interpreted as explicit local authorization; canonical
SNMP-list extras are separately flagged for review. No DNS resolution is performed.

Route evaluation supports simple ordered accept/reject prefix and length conditions.
Complex expressions, jumps and attribute modifications return unknown. ROS6 chains
without explicit terminal behavior are blocked from migration because fall-through
semantics differ. The BNG mesh check inspects configuration evidence; it does not prove
physical cabling, recursive reachability, OSPF state or BGP establishment.

This is a subset of the source project's AGENTS.md. IPv6 baseline enforcement, OSPF
export-scope proofs, aggregate origination/blackhole parity, service VLAN/L2 loop
analysis and a general routing-policy expression interpreter remain future work.

## Reference behavior

See the official
[RouterOS export documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/328155/Configuration+Management),
[RouterOS v6/v7 migration](https://help.mikrotik.com/docs/spaces/ROS/pages/30474256/Moving+from+ROSv6+to+v7+with+examples),
and
[Cisco ACL documentation](https://www.cisco.com/c/en/us/support/docs/security/ios-firewall/23602-confaccesslists.html).
