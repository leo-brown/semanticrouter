"""Browser bridge, strict model hydration and PHP asset-boundary regression cases."""

import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from semanticrouter import load
from semanticrouter.model import FirewallRule, Router
from semanticrouter.serialization import router_from_dict

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location(
    "playground_bridge", ROOT / "playground/bridge.py"
)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class PlaygroundTests(unittest.TestCase):
    def setUp(self):
        self.router = load(ROOT / "tests/fixtures/routeros6.rsc")
        self.request = {
            "routers": [self.router.to_dict()],
            "policy": {"snmp_pollers": ["198.51.100.9"]},
            "selected": self.router.name,
        }

    def call(self, action, **kwargs):
        return json.loads(
            bridge.handle(json.dumps({**self.request, "action": action, **kwargs}))
        )

    def test_model_roundtrip_preserves_typed_nested_objects(self):
        result = router_from_dict(self.router.to_dict())
        self.assertEqual(result.to_dict(), self.router.to_dict())
        self.assertIsInstance(result.firewall_v4.rules[0], FirewallRule)

    def test_platform_contains_only_functional_fields(self):
        self.assertEqual(
            set(self.router.to_dict()["platform"]),
            {"vendor", "os", "version", "family", "hardware"},
        )

    def test_legacy_platform_evidence_is_discarded_on_restore(self):
        data = self.router.to_dict()
        data["platform"]["evidence"] = ["/routing bgp connection"]
        restored = router_from_dict(data)
        self.assertNotIn("evidence", restored.to_dict()["platform"])
        self.assertEqual(restored.platform.family, self.router.platform.family)

    def test_string_boolean_is_rejected(self):
        data = self.router.to_dict()
        data["firewall_v4"]["rules"][0]["enabled"] = "false"
        with self.assertRaises(ValueError):
            router_from_dict(data)

    def test_unrecognised_field_is_rejected(self):
        data = self.router.to_dict()
        data["unrecognised"] = "anything"
        with self.assertRaises(ValueError):
            router_from_dict(data)

    def test_missing_required_field_is_rejected(self):
        with self.assertRaises(ValueError):
            router_from_dict({"role": "edge"})

    def test_probe_uses_same_firewall_engine(self):
        result = self.call(
            "probe", kind="firewall", source="198.51.100.9", protocol="udp", port=161
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["verdict"], "accept")

    def test_route_probe_and_validation(self):
        self.assertEqual(
            self.call(
                "probe", kind="route", chain="TO-BORDER", prefix="203.0.113.1/32"
            )["verdict"],
            "accept",
        )
        self.assertFalse(
            self.call("probe", kind="route", chain="TO-BORDER", prefix="invalid")["ok"]
        )

    def test_export_and_unsupported_target(self):
        self.assertTrue(
            self.call("export", vendor="routeros", version="7.19.3")["complete"]
        )
        self.assertFalse(self.call("export", vendor="routeros", version="7.20")["ok"])

    def test_import_uses_deterministic_parser(self):
        result = self.call(
            "import",
            name="switch-demo",
            text="/system identity set name=switch-demo\n/ip firewall filter add chain=input action=drop",
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["router"]["identity"], "switch-demo")

    def test_model_audit_never_reprocesses_config(self):
        with patch.object(
            bridge,
            "RouterOSRouter",
            side_effect=AssertionError("must not parse configs during model audit"),
        ):
            self.assertTrue(self.call("audit")["ok"])

    def test_variables_are_generic_but_must_be_an_object(self):
        self.assertTrue(self.call("audit", policy={"my_service": {"port": 9999}})["ok"])
        self.assertFalse(self.call("audit", policy=[])["ok"])

    def test_no_rules_means_no_checks_even_with_legacy_flags(self):
        response = self.call("audit", include_estate=True)
        self.assertEqual(response["findings"], [])
        self.assertEqual(response["rule_results"], [])

    def test_semantic_mutation_changes_policy_result(self):
        r = Router("switch-demo", "switch", identity="switch-demo")
        r.firewall_v4.rules = [FirewallRule("input", "drop", enabled=False)]
        self.request["routers"] = [r.to_dict()]
        from semanticrouter.suites import example_suites

        self.request["rules"] = [example_suites()[0]["rules"][0]]
        first = self.call("audit")["findings"]
        self.assertTrue(
            any(f["check"] == "custom.firewall.input-final-drop" for f in first)
        )
        self.request["routers"][0]["firewall_v4"]["rules"][0]["enabled"] = True
        second = self.call("audit")["findings"]
        self.assertFalse(
            any(f["check"] == "custom.firewall.input-final-drop" for f in second)
        )


class VisualiserDeploymentTests(unittest.TestCase):
    def test_operational_snapshot_has_no_public_json_copy(self):
        import contextlib
        import io
        import tempfile

        spec = importlib.util.spec_from_file_location(
            "playground_build", ROOT / "playground/build.py"
        )
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            runtime.mkdir()
            for name in (
                "pyodide.mjs",
                "pyodide.asm.mjs",
                "pyodide.asm.wasm",
                "python_stdlib.zip",
                "pyodide-lock.json",
            ):
                (runtime / name).write_bytes(b"test runtime placeholder")
            output = root / "web"
            with contextlib.redirect_stdout(io.StringIO()):
                builder.build(output, runtime_dir=runtime, visualiser=True)
            self.assertFalse((output / "data.json").exists())
            self.assertFalse((output / "index.html").exists())
            endpoint = (output / "data.php").read_text()
            self.assertTrue(endpoint.startswith("<?php"))
            self.assertLess(
                endpoint.index("requireVisualiserAuth();"),
                endpoint.index("echo base64_decode("),
            )
            page = (output / "index.php").read_text()
            self.assertLess(
                page.index("visualiserAuthValid()"), page.index("<!doctype html>")
            )
            self.assertIn('data-snapshot-url="data.php"', page)
            self.assertIn("Back to Network Visualiser", page)
            self.assertIn('data-runtime-base="runtime.php?file=/"', page)
            self.assertTrue((output / "runtime.php").is_file())

    @unittest.skipUnless(
        __import__("shutil").which("php"),
        "PHP is needed for runtime endpoint regression checks",
    )
    def test_runtime_endpoint_enforces_auth_and_exact_asset_allowlist(self):
        import os
        import shutil
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            web = root / "web"
            web.mkdir()
            (web / "runtime").mkdir()
            (web / "runtime/pyodide.mjs").write_text("export const expected = true;")
            shutil.copyfile(ROOT / "playground/runtime.php", web / "runtime.php")
            (root / "auth.php").write_text(
                "<?php function requireVisualiserAuth() { if (getenv('SEMANTICROUTER_RUNTIME_TEST_AUTH') !== 'yes') { http_response_code(403); exit; } }"
            )
            script = "register_shutdown_function(function(){fwrite(STDERR,(string)http_response_code());}); $_GET['file']=$argv[1]; include $argv[2];"

            def request(name, authenticated):
                environment = {
                    **os.environ,
                    "SEMANTICROUTER_RUNTIME_TEST_AUTH": "yes"
                    if authenticated
                    else "no",
                }
                return subprocess.run(
                    ["php", "-r", script, name, str(web / "runtime.php")],
                    capture_output=True,
                    text=True,
                    env=environment,
                    check=True,
                )

            allowed = request("/pyodide.mjs", True)
            self.assertEqual(allowed.stdout, "export const expected = true;")
            forbidden = request("/pyodide.mjs", False)
            self.assertEqual(forbidden.stderr, "403")
            self.assertEqual(forbidden.stdout, "")
            traversal = request("/../../auth.php", True)
            self.assertEqual(traversal.stderr, "404")
            self.assertEqual(traversal.stdout, "")
