# Rule authoring and the configuration workflow

The workbench starts with **Test design**, followed by source, semantic model, test
results and export. The main test panel shows every active rule, its result counts and a
Run switch. No checks run in a separate hidden path. New workspaces start empty; loading
configs selects no policy. Create a test, import a suite JSON, or explicitly choose an
optional example suite. Adding examples preserves existing definitions with the same ID.
Every rule, including the estate examples, can be edited, disabled or deleted.

Source and model drafts apply only after parsing/validation. Rule drafts become active
only after **Save rule → run tests** validates them. The Python engine evaluates
objects; changing a rule never reparses exports. Failed results open the actual rule
definition. Saved definitions persist in browser storage; suite downloads and workspace
downloads are the portable record. The legacy four saved rules remain ordinary editable
rules.

`semanticrouter/suites/baseline.json` is a minimal optional starting point.
`semanticrouter/suites/brighton.json` contains all 29 former estate checks as editable
expressions with explicit parameters, including `snmp.extra-source`. For that rule,
change `params.snmp_pollers` to change allowed sources, or edit the predicate itself.
Nothing special remains coded behind its check ID.

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
does not prove that all unauthorised SNMP traffic is denied; combine it with an authored
SNMP restriction check and any additional negative packet assertions required.

## Assertion vocabulary

Every file needs a unique `id`, a `name` and an `assert` object. `enabled` defaults to
true and `severity` to P1. Optional `description` documents intent. `params` is a
per-rule JSON object; `suite` is an optional grouping label. An empty `scope` selects
all loaded routers; `roles` and `names` are arrays combined as an intersection. For
example `{"roles":["bng"],"names":["bng-X1","bng-X2"]}`.

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

## Custom logic

Choose **Custom logic** for rules that combine model fields, collections or multiple
routers. Both parameters and the full expression are editable in the form or definition.

```json
{
  "id": "monitoring-sources",
  "name": "SNMP list contains only my pollers",
  "params": { "pollers": ["198.51.100.9"] },
  "assert": {
    "type": "expression",
    "test": {
      "op": "all",
      "items": { "ref": "router.firewall_v4.groups" },
      "as": "entry",
      "test": {
        "op": "or",
        "args": [
          { "op": "ne", "args": [{ "ref": "entry.name" }, "snmp"] },
          { "op": "eq", "args": [{ "ref": "entry.enabled" }, false] },
          {
            "op": "in",
            "args": [
              { "op": "host", "args": [{ "ref": "entry.network" }] },
              { "ref": "params.pollers" }
            ]
          }
        ]
      }
    }
  }
}
```

References: `router` is the current common model, `routers` maps inventory names to
models, `params` contains this rule's parameters, and `vars` contains shared Suite
variables. Collection bindings introduce local names. Operators are explicit JSON; there
is no eval, executable code, file access or network access.

| Operators                                                    | Purpose                                                     |
| ------------------------------------------------------------ | ----------------------------------------------------------- |
| `eq`, `ne`, `gt`, `ge`, `le`, `in`, `contains`, `set_equals` | Compare values and memberships                              |
| `and`, `or`, `not`, `if`                                     | Combine predicates; `if` evaluates only its selected branch |
| `all`, `any`, `filter`, `map`                                | Bind `as` over `items` and evaluate `test`                  |
| `get`, `values`, `length`, `first`, `last`, `enumerate`      | Navigate objects and collections                            |
| `lower`, `concat`, `starts_with`                             | String operations                                           |
| `host`, `prefix_length`, `within`                            | Inspect addresses and prefixes                              |
| `unconditional`, `port_contains`                             | Inspect normalized firewall predicates                      |
| `packet`, `default_only`, `route_range`                      | Invoke generic semantic decision/proof functions            |

Ordinary operators use `{"op":"name","args":[...]}`. Collection operators use
`{"op":"all","items":...,"as":"entry","test":...}`. `enumerate` produces `{index,item}`
objects. `packet` takes router, source, protocol and port. `default_only` takes router
and chain. `route_range` takes router, chain, aggregate, minimum prefix length, maximum
length and expected decision; it exhaustively probes up to 4096 subprefixes per call.
Missing/unsupported decisions are unknown.

Expression `all` uses conventional universal logic: an empty collection is true. Add a
length/presence assertion when existence is required. The simpler field `[]` assertion
retains its stricter empty-match failure. AND/OR preserve unknown unless a definite
false/true resolves the result. Tree depth, node count and evaluation work are bounded.
Some failed collection tests include the mismatching functional values in results.

Suites are JSON objects with `name`, `rules`, optional `id`, `description`, `variables`
and `devices`. CLI: `semanticrouter audit ./configs --rules ./my-suite.json --json`. The
`devices` list optionally selects `.cfg` basenames; otherwise all `.cfg`/`.rsc` files in
the directory are loaded. The same rule evaluator serves Python, CLI and UI.

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
