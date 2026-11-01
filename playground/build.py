"""Build a static playground from the current middleware. No third-party build dependencies.

No --config-dir: synthetic demo only. --config-dir: private deployment snapshots.
Raw config text and credentials are never copied to the output directory.
"""
import argparse
import base64
import json
from pathlib import Path
import shutil
import sys
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from semanticrouter import load
from semanticrouter.policy import audit


def build(output, config_dir=None, runtime_dir=None, download_runtime=False, snapshot=None, visualiser=False):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    for name in ('index.html', 'style.css', 'app.js', 'engine-worker.js', 'topology.js'):
        shutil.copyfile(ROOT/'playground'/name, output/name)
    runtime = output/'runtime'
    runtime.mkdir(exist_ok=True)
    assets = ('pyodide.mjs','pyodide.asm.mjs','pyodide.asm.wasm','python_stdlib.zip','pyodide-lock.json')
    for name in assets:
        target = runtime/name
        if runtime_dir:
            source = Path(runtime_dir)/name
            if source.resolve()!=target.resolve(): shutil.copyfile(source,target)
        elif not target.exists() and download_runtime:
            with urlopen('https://cdn.jsdelivr.net/pyodide/v314.0.7/full/'+name, timeout=60) as response:
                target.write_bytes(response.read())
        if not target.exists():
            raise ValueError('Missing browser runtime. Use --download-runtime or --runtime-dir with a Pyodide 314.0.7 core distribution.')
    (runtime/'NOTICE.txt').write_text('Pyodide 314.0.7 — https://pyodide.org/ — Mozilla Public License 2.0.\nIncludes CPython, distributed under the Python Software Foundation License.\nRuntime assets are unmodified official distribution files.\nhttps://github.com/pyodide/pyodide/blob/314.0.7/LICENSE\nhttps://docs.python.org/3/license.html\n')
    license_target=runtime/'PYODIDE-LICENSE'
    if runtime_dir and (Path(runtime_dir)/'PYODIDE-LICENSE').exists():
        source=Path(runtime_dir)/'PYODIDE-LICENSE'
        if source.resolve()!=license_target.resolve(): shutil.copyfile(source,license_target)
    elif not license_target.exists() and download_runtime:
        with urlopen('https://raw.githubusercontent.com/pyodide/pyodide/314.0.7/LICENSE',timeout=60) as response:
            license_target.write_bytes(response.read())
    bundle = {}
    for path in (ROOT/'semanticrouter').rglob('*'):
        if path.is_file() and not any(part.startswith('.') or part=='__pycache__' for part in path.relative_to(ROOT).parts) and path.suffix in ('.py', '.json'):
            bundle[str(path.relative_to(ROOT))] = path.read_text()
    bundle['playground_bridge.py'] = (ROOT/'playground/bridge.py').read_text()
    (output/'engine.json').write_text(json.dumps(bundle))
    policy = json.loads((ROOT/'examples/brighton.json').read_text())
    if snapshot:
        from semanticrouter.serialization import router_from_dict
        values=json.loads(Path(snapshot).read_text())
        routers=[router_from_dict(value) for value in values['routers']]
        policy=values['policy']
        mode=values.get('mode','saved semantic snapshot')
    elif config_dir:
        routers = [load(Path(config_dir)/(name+'.cfg')) for name in policy['devices']]
        mode = 'private estate snapshot'
    else:
        router = load(ROOT/'tests/fixtures/routeros6.rsc')
        router.name = 'example-bng'
        routers = [router]
        policy = {'devices': [router.name], 'snmp_pollers': ['198.51.100.9'], 'borders': [], 'public_prefixes': ['203.0.113.0/24']}
        mode = 'synthetic demo'
    values = [r.to_dict() for r in routers]
    # Remove local machine paths; keep file/line evidence without transporting raw exports.
    def sanitize(value):
        if isinstance(value, dict):
            return {key: (Path(item).name if key=='path' and isinstance(item,str) else sanitize(item)) for key,item in value.items()}
        if isinstance(value,list): return [sanitize(item) for item in value]
        return value
    data = sanitize({'routers': values, 'policy': policy, 'findings': [f.to_dict() for f in audit(routers,policy)], 'mode': mode})
    if visualiser:
        # Both the HTML entry point and model data use the existing visualiser auth.
        # No operational JSON file is ever written to the web directory.
        guard = "<?php\ndeclare(strict_types=1);\nrequire_once dirname(__DIR__) . '/auth.php';\n"
        page_guard = guard + "if (!visualiserAuthValid()) { header('Location: ../'); exit; }\nheader('Cache-Control: no-store');\n?>\n"
        html = (output/'index.html').read_text().replace('<body>', '<body data-snapshot-url="data.php" data-runtime-base="runtime.php?file=/">')
        html = html.replace('href="./" aria-label="SemanticRouter home"', 'href="../" aria-label="Back to Network Visualiser"')
        (output/'index.php').write_text(page_guard+html)
        encoded = base64.b64encode(json.dumps(data).encode()).decode()
        endpoint = guard + "header('Content-Type: application/json');\nheader('Cache-Control: no-store');\nrequireVisualiserAuth();\necho base64_decode('" + encoded + "');\n"
        (output/'data.php').write_text(endpoint)
        shutil.copyfile(ROOT/'playground/runtime.php',output/'runtime.php')
        (output/'index.html').unlink()
        if (output/'data.json').exists(): (output/'data.json').unlink()
    else:
        (output/'data.json').write_text(json.dumps(data))
    print(f'Built {len(routers)} semantic snapshots ({mode}) in {output}. No raw configs included.')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',default=str(ROOT/'playground/dist'))
    parser.add_argument('--config-dir',help='Include private semantic snapshots from this config directory')
    parser.add_argument('--runtime-dir',help='Directory containing the official Pyodide 314.0.7 core assets')
    parser.add_argument('--download-runtime',action='store_true',help='Fetch missing official Pyodide core assets')
    parser.add_argument('--snapshot',help='Rebuild from a saved semantic workspace JSON instead of source configs')
    parser.add_argument('--visualiser',action='store_true',help='Build PHP-authenticated deployment inside visualiser/semanticrouter/')
    args=parser.parse_args()
    if args.snapshot and args.config_dir: parser.error('Choose either --snapshot or --config-dir')
    build(args.output,args.config_dir,args.runtime_dir,args.download_runtime,args.snapshot,args.visualiser)
