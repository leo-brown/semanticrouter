"""Full original→model→output→model checks, including nonsemantic source fields."""

import json
import unittest
from unittest.mock import patch

from semanticrouter import RouterOSRouter, UnsupportedExport, export_router
from semanticrouter.model import Address, FirewallRule
from semanticrouter.renderers import routeros_native as native
from semanticrouter.serialization import router_from_dict

SOURCE = r"""# exported by RouterOS 7.20.1
# model = CCR2004
/interface ethernet
set [ find default-name="ether1" ] name=uplink l2mtu=9000
/interface bridge
add name=loopback protocol-mode=none
/interface bonding
add name=bond1 mode=802.3ad slaves=ether2,ether3 transmit-hash-policy=layer-2-and-3
/interface vlan
add interface=bond1 name=vlan101-ppp vlan-id=101
/ip address
add address=192.0.2.1 interface=loopback network=192.0.2.1
add address=192.0.2.2 interface=uplink network=192.0.2.3
/ip dns
set servers=1.1.1.1,8.8.8.8 allow-remote-requests=no cache-size=4096KiB
/ip firewall connection tracking
set enabled=no
/ip firewall address-list
add list=snmp address=198.51.100.9 comment="keep this comment"
/ip firewall filter
add chain=input action=accept protocol=udp dst-port=161 src-address-list=snmp connection-state=new comment="SNMP"
add chain=input action=drop comment="final drop"
/ipv6 firewall filter
add chain=input action=drop comment="v6 protection"
/routing bgp instance
add name=main as=64512 router-id=192.0.2.1
/routing bgp connection
add instance=main name=border remote.address=192.0.2.3 remote.as=64512 local.address=192.0.2.2 local.role=ibgp output.filter-chain=OUT output.redistribute=connected,vpn afi=ip
/routing filter rule
add chain=OUT rule="if (dst in 203.0.113.0/24 && dst-len > 24) { set distance 20; accept; }"
/ppp profile
set [ find name="ppp" ] local-address=192.0.2.1 use-compression=no
/interface pppoe-server server
add interface=vlan101-ppp max-mtu=1500 default-profile=ppp authentication=pap,chap disabled=no one-session-per-host=yes
/radius
add address=198.51.100.20 src-address=192.0.2.1 secret="SYNTHETIC-SECRET" timeout=500ms service=ppp
/routing ospf instance
add name=ospf1 version=2 router-id=192.0.2.1
/routing ospf area
add instance=ospf1 name=backbone area-id=0.0.0.0
/routing ospf interface-template
add area=backbone interfaces=uplink type=ptp cost=20
/snmp
set enabled=yes location="Example site" contact="Network team"
/snmp community
set [ find default=yes ] name=SYNTHETIC-COMMUNITY addresses=198.51.100.9/32
/system script
add name=example source=":log info \"literal \$value\";"
/system identity
set name=bng-demo
"""


class CompleteExportTests(unittest.TestCase):
    def setUp(self):
        self.router = RouterOSRouter(
            "bng-demo", SOURCE, path="bng-demo.cfg"
        ).to_common()

    def export(self):
        return export_router(self.router, "routeros", "source")

    def test_unedited_native_statement_order_and_model_are_identical(self):
        result = self.export()
        original = [
            native.signature(item)
            for item in RouterOSRouter("bng-demo", SOURCE).commands
        ]
        generated = [
            native.signature(item)
            for item in RouterOSRouter("bng-demo", result.text).commands
        ]
        self.assertEqual(original, generated)
        self.assertTrue(result.complete)
        self.assertEqual(result.mode, "source-aware")
        self.assertTrue(result.verification["semantic_match"])
        self.assertTrue(result.verification["native_statement_match"])
        self.assertTrue(result.verification["original_statements_match"])
        self.assertTrue(result.verification["original_model_unchanged"])

    def test_semantic_and_native_comparisons_ignore_formatting_and_parameter_order(
        self,
    ):
        first = "/ip address add address=192.0.2.1/32 interface=loopback network=192.0.2.1\n/ip firewall filter add chain=input action=drop disabled=no"
        second = '/ip address\n  add network="192.0.2.1" interface="loopback" address="192.0.2.1/32"\n/ip firewall filter\nadd disabled="no" action="drop" chain="input"'
        a, b = RouterOSRouter("r", first), RouterOSRouter("r", second)
        self.assertEqual(
            native.functional(a.to_common()), native.functional(b.to_common())
        )
        self.assertEqual(
            [native.signature(item) for item in a.commands],
            [native.signature(item) for item in b.commands],
        )

    def test_semantic_comparison_retains_behavioral_rule_order(self):
        first = "/ip firewall filter add chain=input action=accept protocol=icmp\n/ip firewall filter add chain=input action=drop"
        second = "\n".join(reversed(first.splitlines()))
        self.assertNotEqual(
            native.functional(RouterOSRouter("r", first).to_common()),
            native.functional(RouterOSRouter("r", second).to_common()),
        )

    def test_identical_statements_in_different_sections_are_not_confused(self):
        source = "/ip firewall filter\nadd chain=input action=drop\n/ipv6 firewall filter\nadd chain=input action=drop"
        router = RouterOSRouter("r", source).to_common()
        result = export_router(router, "routeros", "source")
        self.assertTrue(result.verification["original_statements_match"])

    def test_model_cannot_inject_a_property_name_as_routeros_code(self):
        self.router.firewall_v4.rules[0].extra["x; /tool fetch url"] = "not-code"
        with self.assertRaisesRegex(UnsupportedExport, "property name"):
            self.export()

    def test_all_features_and_private_fields_remain_in_explicit_full_export(self):
        result = self.export()
        for value in (
            "SYNTHETIC-SECRET",
            "SYNTHETIC-COMMUNITY",
            "one-session-per-host=yes",
            "set distance 20",
            "cost=20",
            "l2mtu=9000",
            "cache-size=4096KiB",
        ):
            self.assertIn(value, result.text)
        public = json.dumps(self.router.to_dict())
        self.assertNotIn("SYNTHETIC-SECRET", public)
        self.assertNotIn("SYNTHETIC-COMMUNITY", public)
        self.assertFalse(
            self.router.bgp.policies[0].supported,
            "native preservation does not pretend to evaluate unknown logic",
        )

    def test_semantic_edits_round_trip_without_losing_unmodeled_properties(self):
        self.router.identity = "edited-router"
        self.router.dns = ["9.9.9.9", "1.0.0.1"]
        self.router.firewall_v4.connection_tracking = True
        self.router.interfaces[0].comment = 'quotes " dollar $ backslash \\ newline\n'
        self.router.radius[0].timeout_ms = 750
        self.router.ppp_servers[0].mtu = 1492
        self.router.ppp_local_addresses["ppp"] = "192.0.2.7"
        self.router.bgp.peers[0].enabled = False
        self.router.snmp_location = "New location"
        result = self.export()
        restored = RouterOSRouter("bng-demo", result.text).to_common()
        self.assertEqual(native.functional(self.router), native.functional(restored))
        self.assertIn('secret="SYNTHETIC-SECRET"', result.text)
        self.assertIn("cache-size=4096KiB", result.text)
        self.assertIn("use-compression=no", result.text)
        self.assertEqual(
            sum(
                item.path == "/ppp profile"
                for item in RouterOSRouter("x", result.text).commands
            ),
            1,
        )
        self.assertFalse(result.verification["original_model_unchanged"])
        self.assertTrue(result.verification["native_statement_match"])

    def test_insert_delete_and_rule_reordering_are_reproduced(self):
        self.router.addresses.pop(0)
        self.router.addresses.append(Address("192.0.2.9/32", "loopback"))
        self.router.firewall_v4.rules.reverse()
        self.router.firewall_v4.rules.insert(
            0, FirewallRule("input", "log", protocol="icmp")
        )
        result = self.export()
        restored = RouterOSRouter("bng-demo", result.text).to_common()
        self.assertEqual(native.functional(self.router), native.functional(restored))
        self.assertIn("connection-state=new", result.text)

    def test_native_coverage_check_catches_loss_invisible_to_common_model(self):
        self.router.radius[0].timeout_ms = 900
        original_tokens = native._tokens
        with patch.object(
            native,
            "_tokens",
            side_effect=lambda text: [
                token
                for token in original_tokens(text)
                if not token.startswith("secret=")
            ],
        ):
            with self.assertRaisesRegex(
                UnsupportedExport, "Native statement comparison failed"
            ):
                self.export()

    def test_full_context_is_explicit_after_json_hydration(self):
        restored = router_from_dict(self.router.to_dict())
        with self.assertRaises(UnsupportedExport):
            export_router(restored, "routeros", "7.19.3")
        result = export_router(restored, "routeros", "source", source_text=SOURCE)
        self.assertTrue(result.complete)

    def test_modern_bgp_is_not_silently_downgraded(self):
        with self.assertRaisesRegex(UnsupportedExport, "7.20"):
            export_router(self.router, "routeros", "7.19.3")
        self.assertTrue(export_router(self.router, "routeros", "7.20.1").complete)

    def test_legacy_source_can_be_preserved_without_forcing_a_migration(self):
        source = "# exported by RouterOS 6.49.10\n/interface bridge add name=bridge1\n/routing bgp instance set default as=64512 router-id=192.0.2.1\n/routing bgp peer add name=p remote-address=192.0.2.2 remote-as=64512 instance=default"
        router = RouterOSRouter("legacy", source).to_common()
        self.assertTrue(export_router(router, "routeros", "source").complete)
        router.bgp.peers[0].enabled = False
        result = export_router(router, "routeros", "source")
        self.assertFalse(
            RouterOSRouter("legacy", result.text).to_common().bgp.peers[0].enabled
        )

    def test_empty_new_version_layout_must_not_be_invented(self):
        source = "# exported by RouterOS 7.19.3\n/routing bgp connection add name=p as=64512 local.role=ibgp remote.address=192.0.2.2 remote.as=64512"
        router = RouterOSRouter("older", source).to_common()
        with self.assertRaisesRegex(UnsupportedExport, "migration mapping"):
            export_router(router, "routeros", "7.20.1")

    def test_redacted_source_is_not_presented_as_complete(self):
        with self.assertRaisesRegex(UnsupportedExport, "redacted"):
            export_router(
                self.router,
                "routeros",
                "source",
                source_text=SOURCE.replace("SYNTHETIC-SECRET", "[REDACTED]"),
            )

    def test_dropping_a_profile_local_address_preserves_other_profile_settings(self):
        self.router.ppp_local_addresses.clear()
        result = self.export()
        self.assertIn("use-compression=no", result.text)
        self.assertEqual(
            RouterOSRouter("bng-demo", result.text).to_common().ppp_local_addresses, {}
        )

    def test_quoted_selector_survives_an_edit(self):
        self.router.interfaces[0].comment = "Updated"
        text = self.export().text
        self.assertIn('[ find default-name="ether1" ]', text)
        self.assertIn("l2mtu=9000", text)

    def test_literal_continuations_and_scripts_are_preserved(self):
        source = '/system script\nadd name=x source=":log info \\"a\\"; \\\n    :log info \\"b\\";"\n/system identity set name=example'
        router = RouterOSRouter("example", source).to_common()
        result = export_router(router, "routeros", "source")
        self.assertTrue(result.complete)
        self.assertEqual(
            [native.signature(item) for item in RouterOSRouter("x", source).commands],
            [
                native.signature(item)
                for item in RouterOSRouter("x", result.text).commands
            ],
        )

    def test_unrepresentable_edits_fail_instead_of_generating_invalid_syntax(self):
        self.router.bgp.peers[0].router_id = "192.0.2.99"
        with self.assertRaisesRegex(UnsupportedExport, "reproduce"):
            self.export()
