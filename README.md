# SemanticRouter

Router configuration as inspectable, testable semantic objects.

SemanticRouter reads exports into vendor-specific feature objects, translates them into
a common model, and runs deterministic configuration checks. Target renderers convert
the supported model features to a concrete vendor and version. The library never
connects to a router, applies a configuration, or uses an ML service.

```text
RouterOS export → vendor objects → common Router / FirewallV4 / BGP
                                          ├── policy assertions
                                          └── vendor + version renderer
```

This is an initial implementation with explicit coverage limits. Python 3.10+ is
required; the core library has no third-party runtime dependencies.

## Quick start

```sh
git clone git@github.com:leo-brown/semanticrouter.git
cd semanticrouter
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .

semanticrouter inspect examples/configs/example-bng.cfg
semanticrouter export tests/fixtures/routeros6.rsc \
  --vendor routeros --version 7.19.3 --output /tmp/migrated.rsc
semanticrouter audit examples/configs --rules semanticrouter/suites/baseline.json
```

No network policy is active by default. Choose or author a suite explicitly. Exit `1`
means an audit contains P1 failures; exit `2` means invalid input, unresolved results,
or an incomplete/unsupported export. P2-only audits exit `0`.

All bundled configs are synthetic documentation-range fixtures. Your own exports stay in
directories you choose. The optional Brighton example supplies estate policy and device
names without bundling operational configs or credentials.

## Browser playground

```sh
python3 playground/build.py --download-runtime
python3 -m http.server 8000 --directory playground/dist
```

Open [localhost:8000](http://localhost:8000). This standalone build needs no PHP,
Visualiser, database, Sites account, API key, or external application. The build
downloads pinned Pyodide assets once; generated pages serve the Python runtime and
middleware from the same origin. System fonts require no external stylesheet.

The workbench starts with **test design → source → semantic model → run tests →
export**. Active rules are prominent choices above the editor, with per-rule Run
switches. A fresh workspace has no active rules. Add an optional example suite or create
your own; importing configs never enables hidden checks. Every assertion, scope,
parameter and priority is editable. Select a router, edit its source or model, and
define reusable rules using a form or JSON. Rules can assert model fields/collections,
ordered input-firewall decisions, reciprocal BGP peerings, and route-filter decisions.
Scope them to roles or named routers. Save a rule to evaluate it against the current
models; inspect pass, fail, unknown and skipped results with links back to the rule or
source evidence.

Saved rules persist in this browser. Download a workspace to retain models, rule files,
policy and attached sources together. Model edits rerun assertions without reparsing
exports. No ML service or connectivity probes are involved. The optional network
overview remains available alongside the editors. See [authoring rules](docs/rules.md)
for the rule schema, examples and result semantics.

See [deployment](docs/deployment.md) for private datasets, offline runtime copies, saved
workspaces, and the optional authenticated PHP Visualiser integration.

## Python API

```python
from semanticrouter import load, export_router
from semanticrouter.policy import input_decision
from semanticrouter.serialization import router_from_dict

router = load("examples/configs/example-bng.cfg")
assert input_decision(router, "198.51.100.9", "udp", 161) == "accept"

restored = router_from_dict(router.to_dict())
result = export_router(restored, "routeros", "7.19.3")
print(result.text)
```

`RouterOSRouter`, `RouterOSFirewallV4` and `RouterOSBGP` retain vendor syntax at the
import boundary. Common dataclasses hold normalized features, source evidence and
explicit limitations. Read [architecture](docs/architecture.md) for module contracts and
extension points.

## Scope and limitations

- RouterOS 6/7 export import, including terse/section syntax and BGP inheritance.
- Supported-subset RouterOS 7.1–7.19 rendering and Cisco IOS 15 input ACL artifacts.
- Ordered firewall/route evaluation, with **unknown distinct from pass**.
- Optional editable example suites, including 29 Brighton estate checks; none
  auto-enabled.
- Composable JSON predicates for collection, cross-router and route-policy assertions.
- Source file/line evidence and strict JSON hydration of common models.

Full exports fail on uncovered features. A partial fragment requires explicit
`--allow-partial`, carries an omission banner, and exits `2`. The renderer produces
additive statements for a prepared target; it is not reconciliation or a deployment
engine. IOS ACL attachment remains an operator decision. Exact firmware cannot be
inferred from hardware or stripped export headers.

See the [capability matrix and policy semantics](docs/capabilities.md) before
interpreting a finding or using a conversion.

## Development

```sh
python3 -m pip install -e '.[dev]'
python3 -m unittest discover -s tests -v
ruff check .
ruff format --check .
node --test tests/*.test.mjs
```

Node 22+ is needed only for JavaScript tests; PHP enables the optional endpoint
regressions. Private-estate tests are opt-in through
`SEMANTICROUTER_CONFIG_DIR=/path/to/net-configs`. See [contributing](CONTRIBUTING.md)
for build, formatting and release checks. CI exercises supported Python versions, the
JavaScript tests, and the installed package outside the source directory.

MIT licensed. The optional Pyodide runtime and CPython retain their own licenses.
