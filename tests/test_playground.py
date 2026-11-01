import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from semanticrouter import load
from semanticrouter.model import Router, FirewallRule
from semanticrouter.serialization import router_from_dict

ROOT=Path(__file__).parents[1]
spec=importlib.util.spec_from_file_location('playground_bridge',ROOT/'playground/bridge.py')
bridge=importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class PlaygroundTests(unittest.TestCase):
    def setUp(self):
        self.router=load(ROOT/'tests/fixtures/routeros6.rsc')
        self.request={'routers':[self.router.to_dict()],'policy':{'snmp_pollers':['198.51.100.9']},'selected':self.router.name}

    def call(self,action,**kwargs):
        return json.loads(bridge.handle(json.dumps({**self.request,'action':action,**kwargs})))

    def test_model_roundtrip_preserves_typed_nested_objects(self):
        result=router_from_dict(self.router.to_dict())
        self.assertEqual(result.to_dict(),self.router.to_dict())
        self.assertIsInstance(result.firewall_v4.rules[0],FirewallRule)

    def test_string_boolean_is_rejected(self):
        data=self.router.to_dict();data['firewall_v4']['rules'][0]['enabled']='false'
        with self.assertRaises(ValueError):router_from_dict(data)

    def test_unrecognised_field_is_rejected(self):
        data=self.router.to_dict();data['unrecognised']='anything'
        with self.assertRaises(ValueError):router_from_dict(data)

    def test_missing_required_field_is_rejected(self):
        with self.assertRaises(ValueError):router_from_dict({'role':'edge'})

    def test_probe_uses_same_firewall_engine(self):
        result=self.call('probe',kind='firewall',source='198.51.100.9',protocol='udp',port=161)
        self.assertTrue(result['ok']);self.assertEqual(result['verdict'],'accept')

    def test_route_probe_and_validation(self):
        self.assertEqual(self.call('probe',kind='route',chain='TO-BORDER',prefix='203.0.113.1/32')['verdict'],'accept')
        self.assertFalse(self.call('probe',kind='route',chain='TO-BORDER',prefix='invalid')['ok'])

    def test_export_and_unsupported_target(self):
        self.assertTrue(self.call('export',vendor='routeros',version='7.19.3')['complete'])
        self.assertFalse(self.call('export',vendor='routeros',version='7.20')['ok'])

    def test_import_uses_deterministic_parser(self):
        result=self.call('import',name='switch-demo',text='/system identity set name=switch-demo\n/ip firewall filter add chain=input action=drop')
        self.assertTrue(result['ok']);self.assertEqual(result['router']['identity'],'switch-demo')

    def test_model_audit_never_reprocesses_config(self):
        with patch.object(bridge,'RouterOSRouter',side_effect=AssertionError('must not parse configs during model audit')):
            self.assertTrue(self.call('audit')['ok'])

    def test_invalid_policy_is_rejected(self):
        self.assertFalse(self.call('audit',policy={'snmp_pollers':['not-an-ip']})['ok'])
        self.assertFalse(self.call('audit',policy={'public_prefixes':['203.0.113.0/25']})['ok'])
        self.assertFalse(self.call('audit',policy={'made-up-rule':True})['ok'])

    def test_semantic_mutation_changes_policy_result(self):
        r=Router('switch-demo','switch',identity='switch-demo')
        r.firewall_v4.rules=[FirewallRule('input','drop',enabled=False)]
        self.request['routers']=[r.to_dict()]
        first=self.call('audit')['findings']
        self.assertTrue(any(f['check']=='firewall.input-final-drop' for f in first))
        self.request['routers'][0]['firewall_v4']['rules'][0]['enabled']=True
        second=self.call('audit')['findings']
        self.assertFalse(any(f['check']=='firewall.input-final-drop' for f in second))


class VisualiserDeploymentTests(unittest.TestCase):
    def test_operational_snapshot_has_no_public_json_copy(self):
        import contextlib
        import io
        import tempfile
        spec=importlib.util.spec_from_file_location('playground_build',ROOT/'playground/build.py')
        builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);runtime=root/'runtime';runtime.mkdir()
            for name in ('pyodide.mjs','pyodide.asm.mjs','pyodide.asm.wasm','python_stdlib.zip','pyodide-lock.json'):
                (runtime/name).write_bytes(b'test runtime placeholder')
            output=root/'web'
            with contextlib.redirect_stdout(io.StringIO()):
                builder.build(output,runtime_dir=runtime,visualiser=True)
            self.assertFalse((output/'data.json').exists())
            self.assertFalse((output/'index.html').exists())
            endpoint=(output/'data.php').read_text()
            self.assertTrue(endpoint.startswith('<?php'))
            self.assertLess(endpoint.index('requireVisualiserAuth();'),endpoint.index('echo base64_decode('))
            page=(output/'index.php').read_text()
            self.assertLess(page.index('visualiserAuthValid()'),page.index('<!doctype html>'))
            self.assertIn('data-snapshot-url="data.php"',page)
            self.assertIn('Back to Network Visualiser',page)
