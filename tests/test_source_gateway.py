"""Original configs are available only through the existing auth and exact snapshot hash."""

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]


@unittest.skipUnless(shutil.which("php"), "PHP is required for source endpoint checks")
class SourceGatewayTests(unittest.TestCase):
    def test_auth_whitelist_snapshot_hash_and_no_credentials_in_bundled_data(self):
        spec = importlib.util.spec_from_file_location(
            "source_gateway_build", ROOT / "playground/build.py"
        )
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            configs = root / "configs"
            configs.mkdir()
            source = "/system identity set name=example\r\n/radius add address=192.0.2.1 secret=SYNTHETIC-SOURCE-SECRET\r\n"
            source_path = configs / "example.cfg"
            source_path.write_bytes(source.encode())
            runtime = root / "runtime"
            runtime.mkdir()
            for name in (
                "pyodide.mjs",
                "pyodide.asm.mjs",
                "pyodide.asm.wasm",
                "python_stdlib.zip",
                "pyodide-lock.json",
            ):
                (runtime / name).write_bytes(b"placeholder")
            with contextlib.redirect_stdout(io.StringIO()):
                builder.build(
                    root / "web",
                    config_dir=configs,
                    runtime_dir=runtime,
                    visualiser=True,
                )
            endpoint = (root / "web/data.php").read_text()
            import re

            data = json.loads(
                base64.b64decode(
                    re.search("echo base64_decode\\('([^']+)'", endpoint)[1]
                )
            )
            self.assertNotIn("SYNTHETIC-SOURCE-SECRET", json.dumps(data))
            self.assertTrue(data["source_redacted"]["example"])
            self.assertEqual(data["source_url"], "source.php")
            digest = hashlib.sha256(source.encode()).hexdigest()
            self.assertEqual(data["source_hashes"]["example"], digest)
            self.assertFalse((root / "web/data.json").exists())
            (root / "auth.php").write_text(
                "<?php function requireVisualiserAuth(){if(getenv('SOURCE_GATEWAY_AUTH')!=='yes'){http_response_code(403);exit;}}"
            )
            script = "register_shutdown_function(function(){fwrite(STDERR,(string)http_response_code());}); $_GET['device']=$argv[1];$_GET['hash']=$argv[2];include $argv[3];"

            def request(device, hash, authenticated=True):
                return subprocess.run(
                    ["php", "-r", script, device, hash, str(root / "web/source.php")],
                    capture_output=True,
                    text=True,
                    env={
                        **os.environ,
                        "SOURCE_GATEWAY_AUTH": "yes" if authenticated else "no",
                    },
                    check=True,
                )

            denied = request("example", digest, False)
            self.assertEqual((denied.stdout, denied.stderr), ("", "403"))
            good = request("example", digest)
            self.assertEqual(
                good.stdout.replace("\r\n", "\n"), source.replace("\r\n", "\n")
            )
            self.assertEqual(request("../configs/example.cfg", digest).stderr, "404")
            self.assertEqual(request("example", "wrong").stderr, "409")
            source_path.write_text(source + "# backup changed\n")
            changed = request("example", digest)
            self.assertEqual(
                changed.stdout.replace("\r\n", "\n"),
                source.replace("\r\n", "\n"),
                "collector changes cannot alter an imported snapshot",
            )
            self.assertEqual(
                request(
                    "example", hashlib.sha256(source_path.read_bytes()).hexdigest()
                ).stderr,
                "409",
            )
