# Architecture

The core boundary is semantic interpretation. Vendor syntax is understood once at
import; tests, browser experiments and renderers consume ordinary common objects. No
module connects to devices or evaluates configuration text as executable code.

## Modules

| Module                                         | Responsibility                                                                        |
| ---------------------------------------------- | ------------------------------------------------------------------------------------- |
| `semanticrouter/model.py`                      | Dataclass feature domains, provenance and explicit unknown/unsupported state          |
| `semanticrouter/definitions.py`                | Bundled firmware definitions and independent hardware/version evidence                |
| `semanticrouter/adapters/routeros/parser.py`   | Non-executing tokenization, sections, continuations, property groups and source lines |
| `semanticrouter/adapters/routeros/firewall.py` | Firewall predicates, address groups and tracking state                                |
| `semanticrouter/adapters/routeros/bgp.py`      | BGP inheritance, redistribution normalization and supported route-rule translation    |
| `semanticrouter/adapters/routeros/router.py`   | Feature assembly and inspection-level addresses/interfaces/services                   |
| `semanticrouter/adapters/routeros/coverage.py` | Command/property coverage independent of inspection success                           |
| `semanticrouter/evaluation.py`                 | Pure, ordered firewall and route evaluation                                           |
| `semanticrouter/policy.py`                     | Brighton estate assertions over common objects                                        |
| `semanticrouter/renderers/`                    | Target-specific RouterOS and IOS syntax                                               |
| `semanticrouter/export.py`                     | Target dispatch and shared completeness enforcement                                   |
| `semanticrouter/serialization.py`              | Strict hydration of JSON into declared dataclass types                                |
| `semanticrouter/cli.py`                        | Inspection/audit/export CLI and documented exit statuses                              |

The public imports `semanticrouter.load`, `RouterOSRouter` and
`semanticrouter.adapters.routeros.parse` remain stable. The RouterOS adapter is a
package so feature implementations can grow without coupling every parser change to
service inspection or target rendering.

## Evidence and uncertainty

A parser command retains vendor attributes, selector text and source file/line. Feature
adapters create normalized objects and discard credentials that have no semantic field.
Unknown firewall matchers remain opaque constraints. Unmodelled commands retain source
references in `Router.unexported`.

These are different questions: can an object be inspected, can a predicate be proved,
and can every imported feature be rendered? A model can support useful inspection while
producing unknown verdicts and blocking complete conversion. `None`, disabled flags,
opaque constraints and diagnostics must survive JSON round-trips. The serializer rejects
misspelled fields and coerces no values.

BGP precedence is instance → inherited parent templates → child template → peer.
Missing/cyclic templates remain diagnostic. Firmware syntax family is separate from an
exact version; conflicting evidence is rejected. `hardware.json` is a reference registry
for extension, not a firmware-version inference table.

## Browser lifecycle

| Module                        | Responsibility                                                     |
| ----------------------------- | ------------------------------------------------------------------ |
| `playground/state.js`         | Tab-local mutable workspace and immutable reset baselines          |
| `playground/dom.js`           | Escaping, status text and explicit downloads                       |
| `playground/engine.js`        | JSON worker transport, request IDs and lifecycle errors            |
| `playground/views.js`         | Inventory, graph, object/experiment/export templates and findings  |
| `playground/app.js`           | User actions, revision control, validation and application startup |
| `playground/topology.js`      | Configured relationship matching, without connectivity claims      |
| `playground/engine-worker.js` | Same-origin Pyodide loading and virtual Python source filesystem   |
| `playground/bridge.py`        | JSON action dispatch to the actual core library                    |
| `playground/build.py`         | Reproducible source/runtime/data assembly for either hosting mode  |

The snapshot renders before Python is ready. A worker boot then runs the same policy
engine as the CLI. User strings are JSON data, never generated Python code. Only an
import action parses an export. Other operations hydrate common models. Revision
counters prevent stale audit responses from overwriting newer edits.

Views receive action callbacks rather than importing mutation logic. Dynamic text is
escaped before HTML insertion. The topology requires reverse BGP endpoint equality to
claim reciprocity; inferred distribution bonds are labelled separately. Neither the
graph nor an enabled flag proves operational state.

## Extending the middleware

1. Add canonical model fields only when their semantics are clear across platforms.
2. Add vendor parsing/translation and retain all unknown constraints.
3. Update firmware mappings and command-property export coverage.
4. Add a target renderer mapping or keep full export blocked.
5. Test behavior: rule order, disabled states, unsupported expressions and round-trip
   meaning, rather than the presence of a string in an export.
6. Document the supported subset and any source/target default differences.

A new estate can call the evaluator directly or implement an independent preset using
common objects. The existing Brighton preset intentionally retains local addressing, DNS
and role conventions; it is not a universal network standard.
