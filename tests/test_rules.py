"""Behavioral checks for authored assertions and review-source redaction."""

import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from semanticrouter import RouterOSRouter
from semanticrouter.model import Address, AddressGroup, BGPPeer, FirewallRule, Router
from semanticrouter.redaction import redact_export
from semanticrouter.rules import run_rules, validate_rules

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location(
    "rule_bridge", ROOT / "playground/bridge.py"
)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


def rule(assertion, **kwargs):
    return {
        "id": "test-rule",
        "name": "My rule",
        "enabled": True,
        "severity": "P1",
        "scope": {},
        "assert": assertion,
        **kwargs,
    }


class AuthoredRuleTests(unittest.TestCase):
    def setUp(self):
        self.router = Router("bng-demo", "bng")
        self.router.firewall_v4.connection_tracking = False
        self.router.firewall_v4.groups = [AddressGroup("snmp", "198.51.100.9")]
        self.router.firewall_v4.rules = [
            FirewallRule(
                "input", "accept", "udp", source_group="snmp", destination_ports="161"
            ),
            FirewallRule("input", "drop"),
        ]

    def result(self, assertion, **kwargs):
        return run_rules([self.router], [rule(assertion, **kwargs)])[0]

    def test_field_pass_then_model_mutation_fails(self):
        assertion = {
            "type": "field",
            "path": "firewall_v4.connection_tracking",
            "operator": "equals",
            "value": False,
        }
        self.assertEqual(self.result(assertion).status, "pass")
        self.router.firewall_v4.connection_tracking = True
        self.assertEqual(self.result(assertion).status, "fail")

    def test_unrecorded_field_is_unknown(self):
        self.assertEqual(
            self.result(
                {
                    "type": "field",
                    "path": "platform.version",
                    "operator": "equals",
                    "value": "7.19",
                }
            ).status,
            "unknown",
        )

    def test_missing_path_is_unknown_and_never_executes(self):
        self.assertEqual(
            self.result(
                {
                    "type": "field",
                    "path": "invented.name",
                    "operator": "equals",
                    "value": 1,
                }
            ).status,
            "unknown",
        )
        for path in (
            "__class__",
            "firewall_v4.__dict__",
            '__import__("os")',
            "radius[-1].timeout_ms",
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate_rules(
                    [rule({"type": "field", "path": path, "operator": "exists"})]
                )

    def test_empty_collection_does_not_pass_vacuously(self):
        self.assertEqual(
            self.result(
                {
                    "type": "field",
                    "path": "bgp.peers[].redistribute",
                    "operator": "includes_all",
                    "value": ["vpn"],
                }
            ).status,
            "fail",
        )

    def test_collection_assertion_requires_every_peer(self):
        self.router.bgp.peers = [
            BGPPeer("one", redistribute=["connected", "vpn"]),
            BGPPeer("two", redistribute=["connected"]),
        ]
        assertion = {
            "type": "field",
            "path": "bgp.peers[].redistribute",
            "operator": "includes_all",
            "value": ["connected", "vpn"],
        }
        self.assertEqual(self.result(assertion).status, "fail")
        self.router.bgp.peers[1].redistribute.append("vpn")
        self.assertEqual(self.result(assertion).status, "pass")

    def test_collection_count_and_boolean_types(self):
        self.assertEqual(
            self.result(
                {
                    "type": "field",
                    "path": "radius",
                    "operator": "count_at_least",
                    "value": 2,
                }
            ).status,
            "fail",
        )
        self.assertEqual(
            self.result(
                {
                    "type": "field",
                    "path": "firewall_v4.connection_tracking",
                    "operator": "equals",
                    "value": 0,
                }
            ).status,
            "fail",
        )

    def test_disabled_and_scope_are_explicit_skips(self):
        assertion = {"type": "field", "path": "identity", "operator": "exists"}
        self.assertEqual(self.result(assertion, enabled=False).status, "skip")
        self.assertEqual(
            self.result(assertion, scope={"roles": ["border"]}).status, "skip"
        )
        self.assertEqual(
            self.result(assertion, scope={"names": ["different-router"]}).status, "skip"
        )

    def test_packet_rule_honours_rule_order_and_disabled_state(self):
        assertion = {
            "type": "packet",
            "source": "198.51.100.9",
            "protocol": "udp",
            "port": 161,
            "decision": "accept",
        }
        self.assertEqual(self.result(assertion).status, "pass")
        self.router.firewall_v4.rules[0].enabled = False
        self.assertEqual(self.result(assertion).status, "fail")

    def test_unknown_packet_predicate_is_unknown(self):
        self.router.firewall_v4.rules[0].extra = {"unmodelled": "yes"}
        self.assertEqual(
            self.result(
                {
                    "type": "packet",
                    "source": "198.51.100.9",
                    "port": 161,
                    "decision": "accept",
                }
            ).status,
            "unknown",
        )

    def test_peer_assertion_matches_reverse_addresses(self):
        border = Router("border-X", "border")
        border.addresses = [Address("192.0.2.1/32", "transit")]
        self.router.addresses = [Address("192.0.2.2/32", "transit")]
        self.router.bgp.peers = [
            BGPPeer("legacy", remote_address="192.0.2.1", local_address="192.0.2.2")
        ]
        border.bgp.peers = [
            BGPPeer("old-gw", remote_address="192.0.2.2", local_address="192.0.2.1")
        ]
        definition = rule(
            {"type": "peers", "targets": ["border-X"], "reciprocal": True},
            scope={"roles": ["bng"]},
        )
        self.assertEqual(
            run_rules([self.router, border], [definition])[0].status, "pass"
        )
        border.bgp.peers[0].local_address = "192.0.2.3"
        self.assertEqual(
            run_rules([self.router, border], [definition])[0].status, "fail"
        )
        self.assertEqual(run_rules([self.router], [definition])[0].status, "unknown")

    def test_route_assertion_uses_ordered_semantic_policy(self):
        r = RouterOSRouter(
            "bng-demo",
            '/routing filter rule add chain=OUT rule="if (dst == 0.0.0.0/0) { accept; }"\n/routing filter rule add chain=OUT rule=reject',
        ).to_common()
        result = run_rules(
            [r],
            [
                rule(
                    {
                        "type": "route",
                        "chain": "OUT",
                        "prefix": "0.0.0.0/0",
                        "decision": "accept",
                    }
                )
            ],
        )[0]
        self.assertEqual(result.status, "pass")

    def test_invalid_rule_files_are_rejected(self):
        valid = rule({"type": "field", "path": "identity", "operator": "exists"})
        for invalid in (
            [valid, valid],
            [{**valid, "severity": "P0"}],
            [{**valid, "enabled": "true"}],
            [{**valid, "assert": {"type": "eval", "code": "print(1)"}}],
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_rules(invalid)

    def test_bridge_returns_pass_results_and_openable_failures(self):
        definition = rule(
            {
                "type": "field",
                "path": "firewall_v4.connection_tracking",
                "operator": "equals",
                "value": True,
            }
        )
        request = {
            "action": "audit",
            "routers": [self.router.to_dict()],
            "policy": {},
            "rules": [definition],
            "include_estate": False,
        }
        with patch.object(
            bridge,
            "RouterOSRouter",
            side_effect=AssertionError("Models must not be reparsed"),
        ):
            response = json.loads(bridge.handle(json.dumps(request)))
        self.assertTrue(response["ok"])
        self.assertEqual(response["rule_results"][0]["status"], "fail")
        self.assertEqual(response["findings"][0]["rule_id"], "test-rule")
        self.assertEqual(response["findings"][0]["check"], "custom.test-rule")

    def test_rule_validation_does_not_need_source_or_models(self):
        definition = rule({"type": "field", "path": "identity", "operator": "exists"})
        response = json.loads(
            bridge.handle(
                json.dumps({"action": "rules_validate", "rules": [definition]})
            )
        )
        self.assertTrue(response["ok"])


class SourceReviewTests(unittest.TestCase):
    def test_credentials_and_private_records_are_redacted_with_line_numbers(self):
        original = '# serial number = PRIVATE\n/radius add address=192.0.2.1 secret="hidden \\"value\\"" timeout=500ms\n/ppp secret add name=private-customer password=hidden2\n/snmp community set [ find default=yes ] name=private-community\n/ip address add address=192.0.2.2 interface=loopback0\n'
        redacted = redact_export(original)
        for secret in (
            "PRIVATE",
            "hidden",
            "private-customer",
            "hidden2",
            "private-community",
        ):
            self.assertNotIn(secret, redacted)
        self.assertEqual(len(original.splitlines()), len(redacted.splitlines()))
        self.assertIn("timeout=500ms", redacted)
        self.assertIn("address=192.0.2.2", redacted)

    def test_continued_credential_statement_cannot_leak_fragments(self):
        source = '/radius add address=192.0.2.1 \\\n secret="very-\\\n sensitive-value"\n/system identity set name=demo\n'
        redacted = redact_export(source)
        self.assertNotIn("sensitive-value", redacted)
        self.assertNotIn("very-", redacted)
        self.assertEqual(len(source.splitlines()), len(redacted.splitlines()))

    def test_reimported_redacted_source_blocks_complete_export(self):
        request = {
            "action": "import",
            "name": "demo",
            "text": "/system identity set name=demo",
            "redacted": True,
        }
        result = json.loads(bridge.handle(json.dumps(request)))
        self.assertTrue(
            any(d["code"] == "redacted-source" for d in result["router"]["diagnostics"])
        )
