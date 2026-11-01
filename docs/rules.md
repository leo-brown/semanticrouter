# Rule authoring and the configuration workflow

The workbench has five stages. Source drafts and JSON model drafts remain separate from
the active models until **Parse → model** or **Apply → run tests** succeeds. Rule drafts
likewise become active only after **Save rule → run tests** validates them. **Run
tests** evaluates saved rules, with an optional built-in estate policy preset. The
Python engine evaluates existing objects; changing a rule never reparses exports.

The explorer contains router models and rule files. Use **New rule** to choose an
assertion template; the form and JSON editor represent the same definition. Duplicate,
delete or download individual rules. Select a failed test to open its rule and router
context. The context pane shows model changes compared with the initial snapshot.
Inventory details such as unavailable exact firmware are collapsed separately from
problems that require configuration changes.

## Example: monitoring access

```json
{
  "id": "monitoring-snmp",
  "name": "Allow the authorised SNMP poller",
  "enabled": true,
  "severity": "P1",
  "scope": {},
  "assert": {
    "type": "packet",
    "source": "35.189.90.14",
    "protocol": "udp",
    "port": 161,
    "decision": "accept"
  }
}
```

This evaluates the ordered IPv4 input policy, including address lists, disabled rules
and the final drop. It does not merely search for an IP string. An unsupported matcher
that could affect the decision returns unknown. This positive-access assertion alone
does not prove that all unauthorised SNMP traffic is denied; combine it with the estate
SNMP restriction check and any additional negative packet assertions required.

## Assertion vocabulary

Every file needs a unique `id`, a `name` and an `assert` object. `enabled` defaults to
true and `severity` to P1. Optional `description` documents intent. An empty `scope`
selects all loaded routers; `roles` and `names` are arrays combined as an intersection.
For example `{"roles":["bng"],"names":["bng-X1","bng-X2"]}`.

| Type     | Required fields                     | Meaning                                                                       |
| -------- | ----------------------------------- | ----------------------------------------------------------------------------- |
| `field`  | `path`, `operator`, usually `value` | Compare platform-independent model values                                     |
| `packet` | `source`                            | Test an IPv4 input packet; defaults: UDP, port 161, accept                    |
| `peers`  | `targets`                           | Require enabled BGP peers to named loaded routers; `reciprocal` defaults true |
| `route`  | `chain`, `prefix`                   | Test a filter chain; `decision` defaults accept, alternative reject           |

Field paths use dotted names and explicit array expansion:
`firewall_v4.connection_tracking`, `radius`, `ppp_servers[].mtu`,
`bgp.peers[].redistribute`. No expressions are executed. Operators are `equals`,
`contains`, `includes_all`, `exists`, `count_at_least`. `contains`/`includes_all`
operate on collection values. Expansion requires **every** resolved value to match; an
empty expansion fails rather than passing vacuously. Missing fields/evidence return
unknown; `exists` on an explicit null fails. Booleans are distinct from numbers. Values
must use JSON syntax, e.g. `false`, `1500`, `["connected", "vpn"]`.

Example assertion fragments:

```json
{
  "type": "field",
  "path": "firewall_v4.connection_tracking",
  "operator": "equals",
  "value": false
}
```

```json
{ "type": "field", "path": "radius", "operator": "count_at_least", "value": 2 }
```

```json
{ "type": "peers", "targets": ["border-X", "border-Y"], "reciprocal": true }
```

Peer assertions match configured peer endpoints to addresses on the named routers,
including reverse endpoints; they do not infer sessions from names or claim live state.
A missing target model is unknown. A present target with missing matching configuration
fails. Field collection counts include disabled objects: use an assertion matching your
actual intent rather than interpreting a count as a service-health guarantee.

## Results and conversion

Each saved rule produces a result for every loaded router: **pass**, **fail**,
**unknown**, or **skip** (disabled/out of scope). Failures use the authored priority;
unknown evidence is not a pass. Rule results include observed values. Failed and unknown
custom results also appear in Problems with links back to their rule.

Export preview chooses vendor/version and lists uncovered source statements with line
navigation. This makes missing import mappings inspectable. Full export remains blocked
when the model has unsupported or omitted features. Explicit partial previews carry
omission diagnostics and are not ready-to-apply configurations.

## Python integration

```python
from semanticrouter.rules import run_rules

results = run_rules(routers, rules)  # list[Router], list[dict]
assert all(result.status in {"pass", "skip"} for result in results)
```

Rules are data, not executable Python. Validation rejects unsupported fields, invalid
assertions and duplicate IDs before evaluation. The evaluator performs no network I/O
and never mutates a router. Browser local storage keeps saved rule files only; download
and open workspaces to move a complete experiment between browsers. Ordinary
source/model drafts are not automatically persisted across refreshes.
