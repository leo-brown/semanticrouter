"""Opt-in integration tests. Operational exports never become public fixtures."""
import json
import os
from pathlib import Path
import unittest
from semanticrouter import load, export_router, UnsupportedExport
from semanticrouter.policy import audit


@unittest.skipUnless(os.environ.get('SEMANTICROUTER_CONFIG_DIR'), 'Set SEMANTICROUTER_CONFIG_DIR for private estate integration tests')
class EstateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy=json.loads((Path(__file__).parents[1]/'examples/brighton.json').read_text())
        root=Path(os.environ['SEMANTICROUTER_CONFIG_DIR'])
        cls.routers=[load(root/(name+'.cfg')) for name in cls.policy['devices']]

    def test_all_twelve_models_and_identities(self):
        self.assertEqual(len(self.routers),12)
        for r in self.routers:
            with self.subTest(r.name):
                self.assertTrue(r.platform.hardware)
                self.assertTrue(r.identity==r.name or r.identity.startswith(r.name+'.'))
                self.assertIsInstance(r.firewall_v4.rules,list)
                for rule in r.firewall_v4.rules:
                    self.assertTrue(rule.chain)
                    self.assertTrue(rule.action)
                    self.assertGreater(rule.source.line,0)
                if r.role in ('bng','border','edge','core'): self.assertTrue(r.bgp.peers)

    def test_private_full_exports_are_explicitly_incomplete(self):
        for r in self.routers:
            with self.subTest(r.name),self.assertRaises(UnsupportedExport):
                export_router(r,'routeros','7.19.3')

    def test_audit_produces_only_known_severities_and_loaded_devices(self):
        findings=audit(self.routers,self.policy)
        self.assertTrue(findings)
        self.assertTrue(all(f.severity in ('P1','P2','UNKNOWN') for f in findings))
        self.assertTrue(all(f.device in self.policy['devices'] for f in findings))

    def test_model_does_not_contain_credential_fields(self):
        for r in self.routers:
            text=json.dumps(r.to_dict())
            for key in ('"password":','"secret":','"private-key":','"serial_number":'):
                self.assertNotIn(key,text)
