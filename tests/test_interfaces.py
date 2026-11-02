"""Explicit interface semantics and lossless edits through RouterOS source export."""

import unittest

from semanticrouter import RouterOSRouter, UnsupportedExport, export_router
from semanticrouter.renderers.routeros_native import functional
from semanticrouter.serialization import router_from_dict

SOURCE = """# exported by RouterOS 7.19.3
/interface bridge
add name=bridge vlan-filtering=yes protocol-mode=rstp
add name=loopback0
/interface ethernet
set [ find default-name=ether1 ] name=ether1-mgmt
set [ find default-name=sfp28-1 ] advertise=25G-baseCR name=transit auto-negotiation=yes
"""


class InterfaceTests(unittest.TestCase):
    def setUp(self):
        self.router = RouterOSRouter("example", SOURCE).to_common()

    def test_explicit_values_are_typed_without_guessing_defaults(self):
        bridge, loopback, management, transit = self.router.interfaces
        self.assertIs(bridge.vlan_filtering, True)
        self.assertIsNone(loopback.vlan_filtering)
        self.assertIsNone(management.advertised_link_modes)
        self.assertEqual(transit.advertised_link_modes, ["25G-baseCR"])
        reordered = SOURCE.replace(
            "add name=bridge vlan-filtering=yes", "add vlan-filtering=yes name=bridge"
        ).replace(
            "advertise=25G-baseCR name=transit", "name=transit advertise=25G-baseCR"
        )
        self.assertEqual(
            functional(self.router),
            functional(RouterOSRouter("example", reordered).to_common()),
        )

    def test_semantic_edits_round_trip_and_preserve_other_native_properties(self):
        self.router.interfaces[0].vlan_filtering = False
        self.router.interfaces[3].advertised_link_modes = [
            "25G-baseCR",
            "25G-baseSR-LR",
        ]
        result = export_router(self.router, "routeros", "source")
        restored = RouterOSRouter("example", result.text).to_common()
        self.assertTrue(result.complete)
        self.assertTrue(result.verification["semantic_match"])
        self.assertTrue(result.verification["native_statement_match"])
        self.assertEqual(functional(self.router), functional(restored))
        self.assertIn("protocol-mode=rstp", result.text)
        self.assertIn("auto-negotiation=yes", result.text)
        self.assertIn("[ find default-name=sfp28-1 ]", result.text)

    def test_explicit_null_removes_a_setting_and_empty_list_remains_explicit(self):
        self.router.interfaces[0].vlan_filtering = None
        self.router.interfaces[3].advertised_link_modes = []
        result = export_router(self.router, "routeros", "source")
        self.assertNotIn("vlan-filtering=", result.text)
        restored = RouterOSRouter("example", result.text).to_common()
        self.assertIsNone(restored.interfaces[0].vlan_filtering)
        self.assertEqual(restored.interfaces[3].advertised_link_modes, [])

    def test_older_workspace_fields_inherit_source_without_mutating_the_caller(self):
        old = self.router.to_dict()
        for item in old["interfaces"]:
            item.pop("vlan_filtering")
            item.pop("advertised_link_modes")
        legacy = router_from_dict(old)
        # Re-saving and restoring an older workspace must not materialize null edits.
        legacy = router_from_dict(legacy.to_dict())
        legacy.interfaces[3].name = "renamed-transit"
        result = export_router(legacy, "routeros", "source", source_text=SOURCE)
        restored = RouterOSRouter("example", result.text).to_common()
        self.assertIs(restored.interfaces[0].vlan_filtering, True)
        self.assertEqual(restored.interfaces[3].advertised_link_modes, ["25G-baseCR"])
        self.assertEqual(restored.interfaces[3].name, "renamed-transit")
        self.assertIsNone(legacy.interfaces[0].vlan_filtering)
        self.assertNotIn("vlan_filtering", legacy.to_dict()["interfaces"][0])

    def test_python_edits_to_new_fields_override_legacy_missing_markers(self):
        data = self.router.to_dict()
        data["interfaces"][0].pop("vlan_filtering")
        legacy = router_from_dict(data)
        legacy.interfaces[0].vlan_filtering = False
        self.assertIs(legacy.to_dict()["interfaces"][0]["vlan_filtering"], False)
        result = export_router(legacy, "routeros", "source", source_text=SOURCE)
        restored = RouterOSRouter("example", result.text).to_common()
        self.assertIs(restored.interfaces[0].vlan_filtering, False)

    def test_new_fields_are_strictly_typed(self):
        data = self.router.to_dict()
        data["interfaces"][0]["vlan_filtering"] = "false"
        with self.assertRaises(ValueError):
            router_from_dict(data)
        data = self.router.to_dict()
        data["interfaces"][3]["advertised_link_modes"] = "25G-baseCR"
        with self.assertRaises(ValueError):
            router_from_dict(data)

    def test_settings_cannot_be_exported_on_the_wrong_interface_kind(self):
        self.router.interfaces[3].vlan_filtering = True
        with self.assertRaisesRegex(UnsupportedExport, "bridge interface"):
            export_router(self.router, "routeros", "source")
