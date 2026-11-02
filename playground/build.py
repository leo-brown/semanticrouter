"""Build a static playground from the current middleware. No third-party build dependencies.

No --config-dir: synthetic demo only. --config-dir: private deployment snapshots.
Originals are included only in the optional guarded PHP export endpoint; public assets
and model/review snapshots exclude original credentials.
"""

import argparse
import base64
import hashlib
import json
import shutil
import sys
from dataclasses import asdict
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from semanticrouter import load  # noqa: E402 -- support direct execution from a clean checkout


def build(
    output,
    config_dir=None,
    runtime_dir=None,
    download_runtime=False,
    snapshot=None,
    visualiser=False,
    inventory=None,
):
    """Create a standalone static playground or an optional authenticated PHP bundle.

    The default dataset is synthetic. Explicit config-directory or saved-workspace
    inputs are serialized as semantic snapshots, with local paths stripped. Runtime
    assets are pinned and served locally. PHP mode writes protected executable
    endpoints instead of a publicly readable operational JSON snapshot.

    The output directory is generated content and may be rebuilt. Do not point it at
    a directory containing hand-maintained source files."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    for name in (
        "index.html",
        "style.css",
        "app.js",
        "engine-worker.js",
        "topology.js",
        "state.js",
        "dom.js",
        "engine.js",
        "views.js",
        "workbench.js",
        "ide.css",
    ):
        shutil.copyfile(ROOT / "playground" / name, output / name)
    runtime = output / "runtime"
    runtime.mkdir(exist_ok=True)
    assets = (
        "pyodide.mjs",
        "pyodide.asm.mjs",
        "pyodide.asm.wasm",
        "python_stdlib.zip",
        "pyodide-lock.json",
    )
    for name in assets:
        target = runtime / name
        if runtime_dir:
            source = Path(runtime_dir) / name
            if source.resolve() != target.resolve():
                shutil.copyfile(source, target)
        elif not target.exists() and download_runtime:
            with urlopen(
                "https://cdn.jsdelivr.net/pyodide/v314.0.7/full/" + name, timeout=60
            ) as response:
                target.write_bytes(response.read())
        if not target.exists():
            raise ValueError(
                "Missing browser runtime. Use --download-runtime or --runtime-dir with a Pyodide 314.0.7 core distribution."
            )
    (runtime / "NOTICE.txt").write_text(
        "Pyodide 314.0.7 — https://pyodide.org/ — Mozilla Public License 2.0.\nIncludes CPython, distributed under the Python Software Foundation License.\nRuntime assets are unmodified official distribution files.\nhttps://github.com/pyodide/pyodide/blob/314.0.7/LICENSE\nhttps://docs.python.org/3/license.html\n"
    )
    license_target = runtime / "PYODIDE-LICENSE"
    if runtime_dir and (Path(runtime_dir) / "PYODIDE-LICENSE").exists():
        source = Path(runtime_dir) / "PYODIDE-LICENSE"
        if source.resolve() != license_target.resolve():
            shutil.copyfile(source, license_target)
    elif not license_target.exists() and download_runtime:
        with urlopen(
            "https://raw.githubusercontent.com/pyodide/pyodide/314.0.7/LICENSE",
            timeout=60,
        ) as response:
            license_target.write_bytes(response.read())
    bundle = {}
    for path in (ROOT / "semanticrouter").rglob("*"):
        if (
            path.is_file()
            and not any(
                part.startswith(".") or part == "__pycache__"
                for part in path.relative_to(ROOT).parts
            )
            and path.suffix in (".py", ".json")
        ):
            bundle[str(path.relative_to(ROOT))] = path.read_text()
    bundle["playground_bridge.py"] = (ROOT / "playground/bridge.py").read_text()
    (output / "engine.json").write_text(json.dumps(bundle))
    from semanticrouter.redaction import redact_export
    from semanticrouter.rules import run_rules
    from semanticrouter.suites import example_suites

    sources = {}
    original_sources = {}
    source_files = {}
    rules = []
    suites = example_suites()
    policy = {}
    if snapshot:
        from semanticrouter.serialization import router_from_dict

        values = json.loads(Path(snapshot).read_text())
        routers = [router_from_dict(value) for value in values["routers"]]
        policy = values["policy"]
        mode = values.get("mode", "saved semantic snapshot")
        sources = {
            name: redact_export(text)
            for name, text in values.get("sources", {}).items()
        }
        rules = values.get("rules", rules)
    elif config_dir:
        directory = Path(config_dir)
        if inventory:
            names = json.loads(Path(inventory).read_text())["devices"]
            paths = [directory / (name + ".cfg") for name in names]
        else:
            paths = sorted(
                path
                for pattern in ("*.cfg", "*.rsc")
                for path in directory.glob(pattern)
                if not path.name.startswith(".")
            )
        if not paths:
            raise ValueError("No .cfg or .rsc exports found in the config directory")
        from semanticrouter.adapters.routeros import RouterOSRouter

        original_bytes = {path.stem: path.read_bytes() for path in paths}
        original_sources = {
            name: content.decode("utf-8") for name, content in original_bytes.items()
        }
        source_files = {
            path.stem: {
                "file": path.name,
                "sha256": hashlib.sha256(original_bytes[path.stem]).hexdigest(),
            }
            for path in paths
        }
        routers = [
            RouterOSRouter(
                path.stem, original_sources[path.stem], str(path)
            ).to_common()
            for path in paths
        ]
        if len({router.name for router in routers}) != len(routers):
            raise ValueError("Config filenames must produce unique router names")
        mode = "private configuration snapshot"
        sources = {
            router.name: redact_export(original_sources[router.name])
            for router in routers
        }
    else:
        router = load(ROOT / "tests/fixtures/routeros6.rsc")
        router.name = "example-bng"
        routers = [router]
        mode = "synthetic demo"
        original_sources = {
            router.name: (ROOT / "tests/fixtures/routeros6.rsc").read_text()
        }
        sources = {name: redact_export(text) for name, text in original_sources.items()}

    if not snapshot:
        # Dataset selection is separate from test intent: no customer IPs or roles
        # become active checks merely because configs were imported.
        policy = {}
    values = [r.to_dict() for r in routers]
    results = run_rules(routers, rules, policy)

    # Remove local machine paths; keep file/line evidence without transporting raw exports.
    def sanitize(value):
        """Strip machine-specific paths recursively while preserving source line evidence."""
        if isinstance(value, dict):
            return {
                key: (
                    Path(item).name
                    if key == "path" and isinstance(item, str)
                    else sanitize(item)
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [sanitize(item) for item in value]
        return value

    data = {
        "routers": sanitize(values),
        "policy": policy,
        "findings": sanitize(
            [
                {
                    "device": result.device,
                    "check": "custom." + result.rule_id,
                    "severity": "UNKNOWN"
                    if result.status == "unknown"
                    else result.severity,
                    "message": result.rule_name + ": " + result.message,
                    "rule_id": result.rule_id,
                    "source": None,
                }
                for result in results
                if result.status in {"fail", "unknown"}
            ]
        ),
        "mode": mode,
        "sources": sources,
        "sources_redacted": True,
        "source_redacted": {
            name: text != original_sources.get(name, "").replace("\r\n", "\n")
            for name, text in sources.items()
        },
        "source_url": "source.php" if visualiser and config_dir else None,
        "source_hashes": {name: item["sha256"] for name, item in source_files.items()}
        if visualiser and config_dir
        else {},
        "rules": rules,
        "rule_results": [asdict(result) for result in results],
        "rule_suites": suites,
    }
    if visualiser:
        # Both the HTML entry point and model data use the existing visualiser auth.
        # No operational JSON file is ever written to the web directory.
        guard = "<?php\ndeclare(strict_types=1);\nrequire_once dirname(__DIR__) . '/auth.php';\n"
        page_guard = (
            guard
            + "if (!visualiserAuthValid()) { header('Location: ../'); exit; }\nheader('Cache-Control: no-store');\n?>\n"
        )
        html = (
            (output / "index.html")
            .read_text()
            .replace(
                "<body>",
                '<body data-snapshot-url="data.php" data-runtime-base="runtime.php?file=/">',
            )
        )
        html = html.replace(
            'href="./" aria-label="SemanticRouter home"',
            'href="../" aria-label="Back to Network Visualiser"',
        )
        (output / "index.php").write_text(page_guard + html)
        encoded = base64.b64encode(json.dumps(data).encode()).decode()
        endpoint = (
            guard
            + "header('Content-Type: application/json');\nheader('Cache-Control: no-store');\nrequireVisualiserAuth();\necho base64_decode('"
            + encoded
            + "');\n"
        )
        (output / "data.php").write_text(endpoint)
        shutil.copyfile(ROOT / "playground/runtime.php", output / "runtime.php")
        gateway = output / "source.php"
        if config_dir:
            # Full originals live only inside this guarded PHP endpoint, separate
            # from public assets and redacted model/review data. Capturing bytes at
            # build time keeps exports tied to the exact imported snapshot.
            originals = {
                name: {
                    **entry,
                    "content": base64.b64encode(
                        original_sources[name].encode()
                    ).decode(),
                }
                for name, entry in source_files.items()
            }
            manifest = base64.b64encode(json.dumps(originals).encode()).decode()
            gateway.write_text(
                (ROOT / "playground/source.php")
                .read_text()
                .replace("__SOURCE_MANIFEST__", manifest)
            )
        elif gateway.exists():
            gateway.unlink()
        (output / "index.html").unlink()
        if (output / "data.json").exists():
            (output / "data.json").unlink()
    else:
        (output / "data.json").write_text(json.dumps(data))
    print(
        f"Built {len(routers)} semantic snapshots ({mode}) in {output}. Credential-redacted source views included."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(ROOT / "playground/dist"))
    parser.add_argument(
        "--config-dir",
        help="Include private semantic snapshots from this config directory",
    )
    parser.add_argument(
        "--inventory",
        help="Optional JSON devices list selecting configs; does not activate rules",
    )
    parser.add_argument(
        "--runtime-dir",
        help="Directory containing the official Pyodide 314.0.7 core assets",
    )
    parser.add_argument(
        "--download-runtime",
        action="store_true",
        help="Fetch missing official Pyodide core assets",
    )
    parser.add_argument(
        "--snapshot",
        help="Rebuild from a saved semantic workspace JSON instead of source configs",
    )
    parser.add_argument(
        "--visualiser",
        action="store_true",
        help="Build PHP-authenticated deployment inside visualiser/semanticrouter/",
    )
    args = parser.parse_args()
    if args.snapshot and args.config_dir:
        parser.error("Choose either --snapshot or --config-dir")
    build(
        args.output,
        args.config_dir,
        args.runtime_dir,
        args.download_runtime,
        args.snapshot,
        args.visualiser,
        args.inventory,
    )
