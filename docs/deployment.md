# Building and hosting the playground

The normal static deployment is self-contained after building. Python 3.10+ builds it
with the standard library; no Node build step, Python package server, database, ML
endpoint or connected application is needed at runtime.

## Standalone static hosting

From the repository root:

```sh
python3 playground/build.py --download-runtime
python3 -m http.server 8000 --directory playground/dist
```

The default build uses a synthetic fixture. Serve `playground/dist/` on any static host
that supports module workers and WebAssembly MIME types. `.mjs` files must be served as
JavaScript, `.wasm` as `application/wasm`. The PHP mode below supplies its own MIME-safe
endpoint for nginx installations without `.mjs` in their MIME map.

The build pins Pyodide 314.0.7, copies its core runtime and includes notices. Runtime
assets are large binary dependencies and are not committed to this source repo. They are
served from the deployment's own origin, not fetched from a CDN while a user is
processing configs. An initial online build uses official distribution URLs; subsequent
builds reuse existing output assets.

For a fully offline build, supply an existing official core distribution:

```sh
python3 playground/build.py --runtime-dir /path/to/pyodide-core
```

The required files are `pyodide.mjs`, `pyodide.asm.mjs`, `pyodide.asm.wasm`,
`python_stdlib.zip` and `pyodide-lock.json`. Include `PYODIDE-LICENSE` too when
available. The builder adds a runtime notice with the upstream license references.

## Private configuration datasets

```sh
python3 playground/build.py --download-runtime \
  --config-dir /path/to/net-configs --output /path/to/private-web-root
```

By default `--config-dir` loads all non-hidden `.cfg`/`.rsc` exports with unique names.
Use `--inventory examples/brighton.json` to select the twelve estate filenames
explicitly. Inventory selection does not activate any tests. The output contains
semantic snapshots, results for saved rules, optional example suites and
credential-redacted source views with original physical line numbers. Credential-bearing
records are omitted and common password/key fields masked. Review copies are not
restorable backups; reimporting one adds a diagnostic that blocks a complete-conversion
claim. They still contain topology, interface comments, addressing and policy: keep an
estate build behind access control and review redaction before sharing unfamiliar vendor
exports.

The output directory is generated content. Do not use a source directory as an output
target. Snapshots reflect build-time exports; rebuild after collecting new backups or
use **Load config** in the browser. Changing a model never edits the source file. Rules
are also saved in browser local storage. **Save workspace** downloads model, source and
rule data; **Open workspace** validates and restores it. Locally loaded source exports
remain in memory until a user explicitly downloads a workspace containing them; such a
download may contain original credentials.

To rebuild a downloaded workspace without its original configs:

```sh
python3 playground/build.py --runtime-dir /path/to/pyodide-core \
  --snapshot /path/to/semanticrouter-workspace.json
```

The supplied models are hydrated with the same strict serializer, then audited again.
Their saved policy and rule definitions travel with them. Attached sources are redacted
again during a build. Use either `--snapshot` or `--config-dir`, not both.

## Optional PHP Visualiser integration

For an existing Network Visualiser with its own `auth.php`:

```sh
python3 playground/build.py --visualiser --download-runtime \
  --config-dir /path/to/net-configs --inventory examples/brighton.json \
  --output /path/to/visualiser/semanticrouter
```

This mode deliberately integrates with the parent application's login. It requires
`visualiserAuthValid()` and `requireVisualiserAuth()` from `../auth.php`; those are not
dependencies of the standalone mode. The page redirects unauthenticated visitors to the
parent Visualiser.

- `index.php` checks page access and points the UI at authenticated data/runtime URLs.
- `data.php` checks access before emitting an embedded semantic snapshot. No public
  operational `data.json` or `index.html` is left in this deployment.
- `runtime.php` checks the same access policy, permits only five exact runtime
  filenames, supplies correct JavaScript/WebAssembly MIME types, and supports HEAD.
- UI and Python source assets contain no operational configs. PHP must execute as PHP;
  do not host this optional output as plain static files.

No parent Visualiser, collector, nginx configuration or credentials file is bundled with
SemanticRouter. The generated directory is ignored by the source repositories. This
adapter is optional because authentication belongs to the application hosting the
dataset, not to the semantic router model itself.

## Troubleshooting

| Symptom                            | Check                                                                                     |
| ---------------------------------- | ----------------------------------------------------------------------------------------- |
| Module import fails                | Confirm HTTP status and JavaScript MIME type for `.mjs`; inspect authentication redirects |
| WebAssembly load fails             | Confirm binary is present, served as `application/wasm`, and matches the pinned release   |
| Snapshot loads but engine does not | Check runtime assets and worker errors; baseline findings are not newly evaluated results |
| PHP returns forbidden              | Use the parent application's established login or trusted-source policy                   |
| Models are stale                   | Rebuild from newer exports or import the exports locally in the browser                   |
| Full export is blocked             | Read omission diagnostics; opt into a fragment only when that is the intended artifact    |

Refresh after deployment so updated UI and worker sources load together. The source
manifest `engine.json` bundles the actual Python modules and firmware definitions; there
is no separately maintained JavaScript policy engine.
