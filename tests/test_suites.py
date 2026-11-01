"""Portable test intent: no hidden defaults, editable policy and bounded expressions."""

import importlib.util
import json
import unittest
from pathlib import Path

from semanticrouter.expressions import validate_expression
from semanticrouter.model import AddressGroup, Router
from semanticrouter.rules import run_rules, validate_rules
from semanticrouter.suites import example_suites, validate_suite

ROOT = Path(__file__).parents[1]


class SuiteTests(unittest.TestCase):
    def setUp(self):
        self.router = Router("my-router", "anything", identity="my-router")
        self.suite = example_suites()[1]

    def example(self, identity):
        return next(rule for rule in self.suite["rules"] if rule["id"] == identity)

    def result(self, rule):
        return run_rules([self.router], [rule])[0]

    def test_library_audit_has_no_assumptions_by_default(self):
        from semanticrouter.policy import audit

        self.assertEqual(audit([self.router]), [])
        self.assertEqual(audit([self.router], []), [])

    def test_all_example_checks_are_visible_editable_data(self):
        self.assertEqual(len(self.suite["rules"]), 29)
        validate_suite(self.suite)
        self.assertTrue(
            all(rule["assert"]["type"] == "expression" for rule in self.suite["rules"])
        )
        self.assertNotIn(
            "193.16.", (ROOT / "semanticrouter/expressions.py").read_text()
        )
        self.assertNotIn("35.189.", (ROOT / "semanticrouter/rules.py").read_text())

    def test_legacy_snmp_rule_is_fully_editable(self):
        rule = self.example("snmp.extra-source")
        self.router.firewall_v4.groups = [AddressGroup("snmp", "52.56.174.0")]
        self.assertEqual(self.result(rule).status, "fail")
        rule["params"]["snmp_pollers"] = ["52.56.174.0"]
        self.assertEqual(self.result(rule).status, "pass")
        rule["assert"]["test"] = {"op": "eq", "args": [1, 2]}
        self.assertEqual(self.result(rule).status, "fail")
        rule["enabled"] = False
        self.assertEqual(self.result(rule).status, "skip")

    def test_scope_and_severity_are_editable(self):
        rule = self.example("dns")
        self.assertEqual(self.result(rule).status, "skip")
        rule["scope"] = {}
        rule["severity"] = "P1"
        result = self.result(rule)
        self.assertEqual(result.status, "fail")
        self.assertEqual(result.severity, "P1")
        self.router.dns = ["10.0.0.53"]
        rule["params"]["dns"] = self.router.dns
        self.assertEqual(self.result(rule).status, "pass")

    def test_missing_data_is_unknown_and_logic_short_circuits(self):
        rule = self.example("identity")
        rule["assert"]["test"] = {
            "op": "eq",
            "args": [{"ref": "router.not_a_field"}, True],
        }
        self.assertEqual(self.result(rule).status, "unknown")
        missing = rule["assert"]["test"]
        rule["assert"]["test"] = {"op": "and", "args": [missing, False]}
        self.assertEqual(self.result(rule).status, "fail")
        rule["assert"]["test"] = {"op": "or", "args": [missing, True]}
        self.assertEqual(self.result(rule).status, "pass")

    def test_expression_validation_rejects_code_and_unbounded_shapes(self):
        for expression in (
            {"op": "eval", "args": ["import os"]},
            {"ref": "router.__class__()"},
            {"op": "eq", "args": [1]},
            {"op": "all", "items": [], "as": "router", "test": True},
        ):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                validate_expression(expression)
        expression = True
        for _ in range(45):
            expression = {"op": "not", "args": [expression]}
        with self.assertRaises(ValueError):
            validate_expression(expression)

    def test_route_proofs_have_an_explicit_limit(self):
        rule = self.example("identity")
        rule["assert"]["test"] = {
            "op": "route_range",
            "args": [{"ref": "router"}, "OUT", "0.0.0.0/0", 1, 32, "accept"],
        }
        result = self.result(rule)
        self.assertEqual(result.status, "unknown")
        self.assertIn("4096", result.message)

    def test_every_example_can_be_disabled_or_removed(self):
        for rule in self.suite["rules"]:
            rule["enabled"] = False
        results = run_rules([self.router], self.suite["rules"])
        self.assertTrue(all(result.status == "skip" for result in results))
        self.assertEqual(run_rules([self.router], []), [])

    def test_generic_variables_are_available_to_any_rule(self):
        rule = self.example("identity")
        rule["assert"]["test"] = {
            "op": "eq",
            "args": [{"ref": "router.role"}, {"ref": "vars.role"}],
        }
        self.assertEqual(
            run_rules([self.router], [rule], {"role": "anything"})[0].status, "pass"
        )

    def test_installed_examples_validate(self):
        for suite in example_suites():
            validate_rules(suite["rules"])

    def test_build_has_no_active_rules_and_only_optional_examples(self):
        import contextlib
        import io
        import tempfile

        spec = importlib.util.spec_from_file_location(
            "suite_build", ROOT / "playground/build.py"
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
                (runtime / name).write_text("placeholder")
            configs = root / "configs"
            configs.mkdir()
            (configs / "generic-device.cfg").write_text(
                "/system identity set name=generic-device"
            )
            (configs / "._ignore.cfg").write_text("not a config")
            with contextlib.redirect_stdout(io.StringIO()):
                builder.build(root / "web", config_dir=configs, runtime_dir=runtime)
            data = json.loads((root / "web/data.json").read_text())
            self.assertEqual(data["routers"][0]["name"], "generic-device")
            self.assertEqual(data["rules"], [])
            self.assertEqual(data["findings"], [])
            self.assertEqual(data["policy"], {})
            self.assertEqual(len(data["rule_suites"]), 2)

    def test_cli_does_not_report_untested_config_as_success(self):
        import contextlib
        import io
        import tempfile

        from semanticrouter.cli import main

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "empty.json"
            path.write_text(json.dumps({"name": "No tests yet", "rules": []}))
            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                status = main(
                    ["audit", str(ROOT / "examples/configs"), "--rules", str(path)]
                )
            self.assertEqual(status, 2)
