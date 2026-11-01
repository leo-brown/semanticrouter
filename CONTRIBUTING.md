# Contributing

Start with [architecture](docs/architecture.md) and
[capabilities](docs/capabilities.md). Preserve unknown meaning, command order, disabled
state and source evidence. Do not turn a partial import or renderer into a complete
conversion by dropping fields.

## Environment and checks

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e '.[dev]'
python3 -m unittest discover -s tests -v
ruff check .
ruff format --check .
node --test tests/*.test.mjs
```

Python 3.10+ runs the library; Node 22+ runs JavaScript-only tests. PHP is optional and
enables endpoint regression tests. No test needs a router connection or ML API. Private
estate tests run only when `SEMANTICROUTER_CONFIG_DIR` is set. Keep their exports and
generated reports out of commits.

Format Python with `ruff format .`. The browser files use Prettier 3.6.2 with the
tracked `.prettierrc.json`; for example:

```sh
npx --yes prettier@3.6.2 --write 'playground/*.{js,css,html,json}' 'tests/*.mjs' '*.md' 'docs/*.md'
```

Detailed comments should explain invariants, units, precedence, unsupported cases and
reasons for conservative behavior. Function names and straightforward assignments do not
need comments that merely repeat the code.

## Packaging and clean-checkout verification

```sh
python3 -m build
python3 -m venv /tmp/semanticrouter-wheel-check
/tmp/semanticrouter-wheel-check/bin/pip install dist/semanticrouter-0.1.0-py3-none-any.whl
```

Run the installed `semanticrouter --help` from outside the checkout to ensure it is
using packaged code/resources. Extract the source distribution separately, run its
tests, and build its synthetic playground with a supplied runtime directory. The source
manifest includes documentation, examples, tests, fixtures and browser source, while
pruning generated datasets and runtime output.

On network-mounted macOS workspaces, build from a clean local copy if the filesystem
creates AppleDouble `._*` sidecars. Never publish those files or a generated estate
snapshot as part of an open-source artifact.

## Scope and review

Keep parsers non-executing, evaluators free of I/O, renderers separate by vendor, and
browser policy evaluation in the Python worker. New properties need both an inspection
mapping and explicit export coverage; these are separate contracts. Use behavioral
counterexamples for security-sensitive predicates and conversion loss. Describe target
version limits, tests and material limitations in changes.
