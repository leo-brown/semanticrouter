"""Opt-in integration tests. Operational exports never become public fixtures."""

import json
import os
import unittest
from pathlib import Path

from semanticrouter import export_router, load
from semanticrouter.policy import audit_brighton as audit
from semanticrouter.redaction import redact_export
from semanticrouter.rules import run_rules
from semanticrouter.suites import example_suites


@unittest.skipUnless(
    os.environ.get("SEMANTICROUTER_CONFIG_DIR"),
    "Set SEMANTICROUTER_CONFIG_DIR for private estate integration tests",
)
class EstateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = json.loads(
            (Path(__file__).parents[1] / "examples/brighton.json").read_text()
        )
        root = Path(os.environ["SEMANTICROUTER_CONFIG_DIR"])
        cls.routers = [load(root / (name + ".cfg")) for name in cls.policy["devices"]]

    def test_all_inventory_models_and_identities(self):
        self.assertEqual(len(self.routers), len(self.policy["devices"]))
        for r in self.routers:
            with self.subTest(r.name):
                self.assertTrue(r.platform.hardware)
                self.assertTrue(
                    r.identity == r.name or r.identity.startswith(r.name + ".")
                )
                self.assertIsInstance(r.firewall_v4.rules, list)
                for rule in r.firewall_v4.rules:
                    self.assertTrue(rule.chain)
                    self.assertTrue(rule.action)
                    self.assertGreater(rule.source.line, 0)
                if r.role in ("bng", "border", "edge", "core"):
                    self.assertTrue(r.bgp.peers)

    def test_private_full_exports_round_trip_every_original_statement(self):
        for r in self.routers:
            with self.subTest(r.name):
                result = export_router(r, "routeros", "source")
                self.assertTrue(result.complete)
                self.assertTrue(result.verification["semantic_match"])
                self.assertTrue(result.verification["native_statement_match"])
                self.assertTrue(result.verification["original_statements_match"])
                self.assertEqual(
                    result.verification["input_statements"],
                    result.verification["output_statements"],
                )

    def test_audit_produces_only_known_severities_and_loaded_devices(self):
        findings = audit(self.routers, self.policy)
        self.assertTrue(findings)
        self.assertTrue(all(f.severity in ("P1", "P2", "UNKNOWN") for f in findings))
        self.assertTrue(all(f.device in self.policy["devices"] for f in findings))

    def test_model_does_not_contain_credential_fields(self):
        for r in self.routers:
            text = json.dumps(r.to_dict())
            for key in (
                '"password":',
                '"secret":',
                '"private-key":',
                '"serial_number":',
            ):
                self.assertNotIn(key, text)

    def test_authored_rules_evaluate_private_models_and_mutations(self):
        from copy import deepcopy

        rules = example_suites()[1]["rules"]
        results = run_rules(self.routers, rules)
        self.assertEqual(len(results), len(rules) * len(self.routers))
        self.assertTrue(
            all(r.status in {"pass", "fail", "unknown", "skip"} for r in results)
        )
        router = deepcopy(next(r for r in self.routers if r.role == "bng"))
        assertion = next(rule for rule in rules if rule["id"] == "bng.conntrack")
        router.firewall_v4.connection_tracking = False
        self.assertEqual(run_rules([router], [assertion])[0].status, "pass")
        router.firewall_v4.connection_tracking = True
        self.assertEqual(run_rules([router], [assertion])[0].status, "fail")

    def test_bundled_sources_do_not_include_private_credential_values(self):
        import re

        root = Path(os.environ["SEMANTICROUTER_CONFIG_DIR"])
        for name in self.policy["devices"]:
            original = (root / (name + ".cfg")).read_text()
            redacted = redact_export(original)
            self.assertEqual(len(original.splitlines()), len(redacted.splitlines()))
            for match in re.finditer(
                r'\b(?:password|secret|private-key|preshared-key)=("(?:\\.|[^"\\])*"|[^\s]+)',
                original,
            ):
                credential = match.group(1).strip('"')
                if len(credential) >= 6:
                    # Compare in memory; assertion text deliberately never includes a credential.
                    self.assertFalse(
                        credential in redacted,
                        "A private credential remains in the source view",
                    )
