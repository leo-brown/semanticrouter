# SemanticRouter

SemanticRouter imports router configuration into vendor objects, translates those
objects into a common model, and runs configuration assertions against that model.
Target adapters render supported features for a specific vendor and firmware version.
It never connects to routers or claims to test connectivity.

```text
RouterOS export -> RouterOSRouter / RouterOSFirewallV4 / RouterOSBGP
                                      |
                                  to_common()
                                      |
                       Router / FirewallV4 / BGP
                           |                 |
                     policy assertions   target renderer
                                      (vendor + version)
```

This is an initial implementation, with a useful estate audit and intentionally
limited migration coverage. It is not a universal router configuration converter.
Python 3.10+; no runtime dependencies.

## Run

From this checkout, without installing anything:

```sh
python3 -m unittest discover -s tests -v
python3 -m semanticrouter inspect /path/to/router.cfg
python3 -m semanticrouter audit /path/to/net-configs --policy examples/brighton.json --output .local/audit.json
```

Create `.local/` before saving there. Alternatively, install with `pip install -e .`
and use `semanticrouter` directly. The Brighton policy selects precisely the twelve
requested devices. Configs remain in the caller's directory; no operational exports,
PPP credentials, RADIUS secrets or generated estate reports are bundled in this repo.
Only synthetic documentation-range fixtures are committed.

Exit codes: `0` successful inspection/export or an audit with no failures/unknowns;
`1` audit has P1 failures; `2` incomplete/unknown result, unsupported conversion,
invalid input or explicitly requested partial export. P2-only audits exit zero.

## Use semantic objects in tests

```python
from semanticrouter import load
from semanticrouter.policy import input_decision, audit

router = load('/path/to/net-configs/bng-X1.cfg')
assert router.firewall_v4.connection_tracking is False
assert input_decision(router, '35.189.90.14', protocol='udp', port=161) == 'accept'
assert all(set(peer.redistribute) == {'connected', 'vpn'}
           for peer in router.bgp.peers
           if peer.enabled and peer.role in ('ibgp', 'ibgp-rr'))
```

Common objects are ordinary Python dataclasses: inspect them, change them in memory,
or create synthetic routers directly. `router.to_dict()` serializes the intermediate
model to JSON. Raw commands stay in the vendor adapter; common objects retain source
file/line references and unresolved-feature diagnostics. Unknown vendor firewall
predicates are retained as opaque constraints and prevent a match from being treated
as unconditional. Use `semanticrouter.serialization.router_from_dict()` to validate and hydrate typed common objects from JSON.

## Import and firmware definitions

`semanticrouter/firmware/` holds separate firmware definitions for RouterOS 6,
RouterOS 7, and Cisco IOS 15, plus a hardware-family registry. The definitions carry
syntax markers, BGP field mappings and target capability/version metadata. Add a
separate definition and adapter tests when a firmware train changes semantics.
Version-specific translation logic lives in the adapter, not in the policy tests.

* RouterOS terse and section-based exports, quoted values, backslash continuations,
  selectors and abbreviated property groups (`local.address=... .role=...`).
* Exact firmware comes from the RouterOS export header or `--source-version`.
* Syntax can establish family 6 or 7; it cannot establish an exact release. Conflicting
  evidence is rejected. Header model is stored independently as hardware identity.
* Hardware does **not** establish firmware. In particular, a CRS326/CRS518 export
  without distinguishing syntax remains an unknown software family.
* These estate exports replace the version-bearing header with
  `# <Removed ROS Timestamp>`. Eight routing nodes have RouterOS 7 syntax evidence;
  four switches have insufficient evidence. None yields an exact version.
* Non-executing parser only: this is an export reader, not a RouterOS script engine.
  It cannot evaluate arbitrary scripts, device-dependent selectors or runtime state.
  Commands/properties outside export coverage remain explicitly unexported.
* This release does not reconstruct arbitrary ordered `add/set/remove` edit scripts.
  Supply a device export snapshot. `set` support is for exported settings, BGP
  defaults, interface metadata and named PPP profiles; selector ambiguity is reported.

## Capabilities

| Feature | RouterOS 6/7 import | RouterOS 7.1–7.19 export | Cisco IOS 15 export |
|---|---|---|---|
| Identity, DNS | Yes | Supported fields | Supported fields |
| IPv4 input/other filter rules and address groups | Yes, unknown predicates opaque | Supported predicates/actions | Input ACL artifact, restricted predicates |
| IPv4 addressing | Yes, including host-style loopbacks/peers | Ordinary addresses; host-peer semantics block full export | Not yet |
| BGP peers, inheritance, simple route policies | Yes | Supported fields and grammar | Not yet |
| Interfaces/bonds/VLANs, PPPoE/profiles, RADIUS, SNMP | Inspection subset | Not yet | Not yet |
| OSPF interface templates | Interface-name inspection | Not yet | Not yet |
| Arbitrary scripts, NAT/raw/mangle, DHCP, MPLS/VPLS, bridges | Preserved as uncovered source references | Not yet | Not yet |

The common model mirrors the vendor feature domains, not every vendor property.
Omitted defaults and unmodelled behavior remain a material limitation. A `complete`
export means all imported configuration commands are covered by the supported
semantic mapping; it does not certify a deployable configuration or recreate hidden
defaults. The initial renderers produce configuration additions for a prepared target,
not idempotent reconciliation or an in-place update of an existing router.

## Migration examples

A synthetic RouterOS 6 BGP/firewall fixture demonstrates a complete supported-subset
migration, including instance redistribution and prefix-length filter conversion:

```sh
python3 -m semanticrouter export tests/fixtures/routeros6.rsc --vendor routeros --version 7.19.3 --output /tmp/migrated.rsc
```

RouterOS 7.20+ BGP instance syntax needs a separate renderer and is explicitly rejected
in this release. This limit is stored in the firmware definition. Early RouterOS 6
minor releases are parsed by syntax family; only the supplied synthetic 6.49-style
fixture has migration regression coverage so far.

Full exports fail if any source command/property or modeled feature cannot be
translated. To deliberately request a fragment:

```sh
python3 -m semanticrouter export /path/to/router.cfg --vendor cisco-ios --version 15.2 --allow-partial --output /tmp/input-acl.ios
```

Partial output carries a banner, reports omissions to stderr and exits `2`. IOS output
is a named IPv4 ACL artifact: the operator must choose its interface/control-plane
attachment. RouterOS input has no automatic device-wide IOS ACL equivalent. There is
no IOS importer yet. Never apply a fragment as if it were a full replacement config.

## Estate assertions

`examples/brighton.json` contains estate intent separately from the middleware.
`policy.audit()` operates on common objects only, with no dependency on RouterOS text.

Implemented checks include:

* Enabled, unconditional terminal IPv4 input drop/reject; rule-order-aware SNMP
  access for each canonical poller, legacy/extra monitoring sources and SNMP location.
* RouterOS family policy and unknown exact firmware, hardware observations, identity,
  infrastructure loopbacks, DNS, explicit LACP and disabled production-looking uplinks.
* BNG conntrack disabled; PPPoE placement, MTU, authentication and profile; PPP/RADIUS
  source identity, two RADIUS servers and ordered 500ms/2000ms timeouts.
* BNG distribution uplinks and both-border mesh: active address/session matching,
  reciprocal sessions (including `gw-*` names), named transit, OSPF template and
  explicit OSPF input allow on that transit.
* Connected+VPN redistribution and all customer more-specifics in the six /24 blocks.
  Every /25 through /32 is evaluated: 510 routes per aggregate, not a string-presence
  test. Matching reciprocal border input chains are tested too.
* Default-only border-to-BNG export on the actual reciprocal peer's applied policy.

`UNKNOWN` is distinct from pass. Firewall packet evaluation is deliberately limited:
unknown matches fork possible paths and return a definite verdict only when outcomes
agree. Interface-scoped management accepts are permitted by the source-restriction
lint; interface topology and the authorization of management networks are not proved.
Source-restricted accepts are interpreted as explicit local authorization; canonical
SNMP-list extras are separately flagged for review. No DNS resolution is performed.

Route evaluation supports simple ordered accept/reject prefix and length conditions.
Complex expressions, jumps and attribute modifications return unknown. ROS6 chains
without explicit terminal behavior are blocked from migration because fall-through
semantics differ. The BNG mesh check inspects configuration evidence; it does not
prove physical cabling, recursive reachability, OSPF state or BGP establishment.

This is a subset of the source project's AGENTS.md. IPv6 baseline enforcement,
OSPF export-scope proofs, aggregate origination/blackhole parity, service VLAN/L2 loop
analysis and a general routing-policy expression interpreter remain future work.

## Tests and contributing

```sh
python3 -m unittest discover -s tests -v
SEMANTICROUTER_CONFIG_DIR=/path/to/net-configs python3 -m unittest discover -s tests -v
```

Synthetic regression tests cover parsing, firmware evidence, inheritance, rule order,
unknown/disabled predicates, semantic mutation, reciprocal mesh matching, migration,
export rejection, secret exclusion and CLI exit behavior. Optional estate tests load
all twelve real configs without copying them into the repository. CI runs synthetic
tests on Python 3.10–3.13.

When adding a feature: add a common object, implement the vendor adapter, declare its
firmware coverage, and add behavioral tests that distinguish supported semantics from
unknown data. Do not mark a conversion complete by dropping unknown attributes.

Reference behavior follows MikroTik's official documentation:
[configuration exports](https://help.mikrotik.com/docs/spaces/ROS/pages/328155/Configuration+Management),
[v6 to v7 migration](https://help.mikrotik.com/docs/spaces/ROS/pages/30474256/Moving+from+ROSv6+to+v7+with+examples),
[BGP properties](https://help.mikrotik.com/docs/spaces/ROS/pages/331612228/routing+bgp),
and [Cisco ACL syntax](https://www.cisco.com/c/en/us/support/docs/security/ios-firewall/23602-confaccesslists.html).

Licensed under MIT.

## Browser playground

The buildless web UI runs the same Python parser, common objects, policy engine and
exporters inside a dedicated Pyodide Web Worker. There is no ML/API processing and
no duplicated JavaScript implementation of the network rules. Configs selected or
pasted into the playground are parsed locally in browser memory. Auditing an edited
model never reparses its source config. Changes are ephemeral until downloaded.

```sh
python3 playground/build.py --download-runtime
python3 -m http.server 8000 --directory playground/dist
```

Open `http://localhost:8000`. The default build includes only a synthetic fixture.
For a private deployment with the twelve estate routers, add
`--config-dir /path/to/net-configs`. This includes semantic snapshots and baseline
findings, never the raw exports. Keep that generated output private; it still
contains network topology and addressing. `playground/dist/` is excluded from Git.
Use `--runtime-dir /path/to/pyodide-core` to build without downloading the runtime.
The build pins Pyodide 314.0.7 and serves its core assets from the same origin.

Select nodes to inspect firewall, BGP, interfaces, addressing and subscriber
services. The Experiment tab supports rule/peer toggles, MTU and conntrack changes,
RADIUS timeout adjustments, and packet/route probes. The JSON tab validates and
applies direct model edits. Export previews identify unsupported mappings. Edit policy to change canonical pollers, required borders and public prefixes. Reset
restores the bundled snapshot. A downloaded workspace can be rebuilt with
`--snapshot /path/to/workspace.json`. Relationship lines show configuration evidence,
including inferred distribution uplinks; they are not a live topology monitor.

Pyodide is distributed under MPL-2.0 and includes CPython under the PSF license;
see the unmodified distribution notices. Loading the runtime requires WebAssembly
and Web Worker support. Files are not uploaded to a backend, and nothing applies
changes to network devices. Workspace/report downloads may contain network data.

Topology relationship regressions also run with `node --test tests/topology.test.mjs` (Node 22+). Reverse BGP endpoints must match before a relationship is labelled reciprocal.
