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
Use `--inventory examples/brighton.json` to select the fourteen estate filenames
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
- `source.php` is generated only for a private config-directory build. It uses the same
  authentication, exact device whitelist and SHA-256 snapshot checks before supplying an
  original on an explicit export request. Backups that changed since build return 409.
  The config directory must remain readable by PHP at its deployed relative path.
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
| Full export is blocked             | Use the original config and source target; inspect layout/round-trip diagnostics          |

Refresh after deployment so updated UI and worker sources load together. The source
manifest `engine.json` bundles the actual Python modules and firmware definitions; there
is no separately maintained JavaScript policy engine.

## Named workspaces, GitHub teams and Git config sync

The sidebar creates empty workspaces or copies the current models/tests. Save and switch
between named browser workspaces; file import/export remains available. Rule definitions
and unfinished editor sessions are scoped to their workspace. Browser storage has a
quota; a failed save leaves the current work intact. Only saved models/rules enter a
shared or exported snapshot. Empty workspaces can author tests before importing devices.

PHP deployments include GitHub sign-in and team workspace storage. The default is a
private SQLite store in a mode-0700 directory under
`/var/tmp/semanticrouter-<installation hash>/`, outside the web root. Set
`SEMANTICROUTER_DATA_DIR` to an administrator-managed persistent directory such as
`/var/lib/semanticrouter` for production retention/backup policy. Alternatively
configure `SEMANTICROUTER_DB_DSN`, `SEMANTICROUTER_DB_USER` and
`SEMANTICROUTER_DB_PASSWORD`. SQLite DSNs must point outside the web root. The DB
account needs permission to create the isolated `semanticrouter_*` tables. No account,
secret or private database belongs in Git. Back up the selected database as part of the
host's normal backup process.

Open **Team & login → GitHub sign-in setup** from an existing BF administrator session.
The screen provides a registration link and exact callback URL, then accepts the OAuth
Client ID and Client Secret into the private database. For this deployment the callback
is `https://monitoring.brightonfibre.com/visualiser/semanticrouter/oauth_callback.php`.
Environment settings `SEMANTICROUTER_GITHUB_CLIENT_ID`,
`SEMANTICROUTER_GITHUB_CLIENT_SECRET` and `SEMANTICROUTER_GITHUB_CALLBACK_URL` can
override stored settings. This registration is a one-time action in the GitHub
organisation; the middleware cannot invent or register those credentials itself.

The
[GitHub web flow](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
uses state, PKCE and server-side code exchange. Only `read:user` is requested. Access
tokens are discarded after verifying `/user`; repository permissions are not requested.
New users start empty and can create teams. Owners create seven-day, single-use
invitation links bound to a stable GitHub numeric id, so a username rename cannot grant
the wrong account membership. Invitation secrets stay in URL fragments until explicit
sign-in. Workspace reads/writes require membership; revision checks reject stale
teammate saves.

BF data and original-source endpoints retain their separate BF access guard. Team login
alone exposes neither. Sharing the current BF model to a team is an explicit save
action; a redacted shared review is not an original backup for complete export.

**Sync config repository** is pull-and-review only. Choose the repository, ref and
config directory, preview additions/changes/conflicts/removals, and import selected
files. Both source and model drift produce conflicts. Deletions and conflicts are
opt-in. The complete candidate is parsed and audited before applying. Nothing commits or
pushes to the repo. Private repositories need read-only deploy-key access for the PHP
service account; `SEMANTICROUTER_GIT_SSH_KEY` selects an installed key. Install the
verified Git host key in that account's SSH known-hosts file. OAuth identity does not
supply repo access.

GitHub, GitLab and Bitbucket hosts are enabled by default; administrators can set the
comma-separated `SEMANTICROUTER_GIT_HOSTS` for another trusted host. Git uses a
temporary bare repository, no checkout/hooks/submodules, restricted transports, bounded
processes, and a single concurrent sync. Only UTF-8 `.cfg`, `.rsc` and `.txt` blobs are
imported; symlinks and hidden files are skipped. Limits are 100 configs, 5 MB each, 10
MB combined, 100 MB fetched packs and 25 seconds per Git process. PHP needs PDO,
sessions, cURL and `proc_open`; Git/SSH must be installed on the server.

A standalone team server can be built with:

```sh
python3 playground/build.py --teams --download-runtime --output /srv/semanticrouter
```

Set a private database DSN and GitHub OAuth credentials in the PHP service environment.
An installation administrator may use `SEMANTICROUTER_SETUP_TOKEN` with the
`X-Semanticrouter-Setup` header for initial setup. Team-only builds publish no bundled
operational snapshot; configs enter through authenticated workspace imports or Git sync.
