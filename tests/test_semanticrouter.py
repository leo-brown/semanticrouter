"""Behavioral regression cases for lexical parsing, semantic evaluation and conversion loss."""

import json
import tempfile
import unittest
from pathlib import Path

from semanticrouter import RouterOSRouter, UnsupportedExport, export_router, load
from semanticrouter.adapters.routeros import parse
from semanticrouter.cli import main
from semanticrouter.model import AddressGroup, FirewallRule, Interface, Router
from semanticrouter.policy import audit, default_only, input_decision, route_decision


def model(text, version=None, name="bng-X1"):
    return RouterOSRouter(name, text, version=version).to_common()


class ParserTests(unittest.TestCase):
    def test_terse_and_section_equivalence(self):
        a = model("/ip firewall filter add chain=input action=drop")
        b = model("/ip/firewall/filter\nadd action=drop chain=input")
        self.assertEqual(a.firewall_v4.rules[0].action, b.firewall_v4.rules[0].action)

    def test_quotes_continuation_and_escapes(self):
        commands = list(
            parse(
                '/system identity\nset name="two words \\"ok\\"" \\\n comment="escaped\\24value"'
            )
        )
        self.assertEqual(commands[0].attributes["name"], 'two words "ok"')
        self.assertEqual(commands[0].attributes["comment"], "escaped$value")
        self.assertEqual(commands[0].source.line, 2)

    def test_invalid_quotes_rejected(self):
        with self.assertRaises(ValueError):
            list(parse('/system identity set name="oops'))

    def test_truncated_continuation_rejected(self):
        with self.assertRaises(ValueError):
            list(parse("/system identity set name=x \\"))

    def test_grouped_property_names(self):
        p = model(
            "/routing bgp connection add name=x local.address=192.0.2.1 .role=ibgp output.filter-chain=OUT .redistribute=connected,vpn remote.address=192.0.2.2 .as=64512 as=64512"
        ).bgp.peers[0]
        self.assertEqual(
            (p.role, p.export_policy, p.remote_as), ("ibgp", "OUT", "64512")
        )
        self.assertEqual(p.redistribute, ["connected", "vpn"])

    def test_loopback_field_order(self):
        r = model(
            "/ip address add comment=Loopback interface=loopback0 network=193.16.0.12 address=193.16.0.12"
        )
        self.assertEqual(r.addresses[0].address, "193.16.0.12/32")

    def test_version_is_not_hardware(self):
        r = model("# model = CRS326-24S+2Q+\n/system identity set name=switch-X1")
        self.assertIsNone(r.platform.version)
        self.assertIsNone(r.platform.family)
        self.assertEqual(r.platform.hardware, "CRS326-24S+2Q+")

    def test_syntax_family_not_exact_version(self):
        r = model("/routing bgp connection add name=x")
        self.assertEqual(r.platform.family, "7")
        self.assertIsNone(r.platform.version)

    def test_conflicting_version_rejected(self):
        with self.assertRaises(ValueError):
            model("/routing bgp connection add name=x", "6.49.10")

    def test_template_inheritance(self):
        r = model(
            "/routing bgp template add name=base as=64512 output.redistribute=connected,vpn\n/routing bgp template add name=child templates=base\n/routing bgp connection add name=x templates=child remote.address=192.0.2.2 .as=64512 local.role=ibgp"
        )
        self.assertEqual(r.bgp.peers[0].local_as, "64512")
        self.assertEqual(r.bgp.peers[0].redistribute, ["connected", "vpn"])

    def test_template_cycle_reported(self):
        r = model(
            "/routing bgp template add name=a templates=b\n/routing bgp template add name=b templates=a\n/routing bgp connection add name=x templates=a"
        )
        self.assertTrue(any(d.code == "bgp-inheritance" for d in r.diagnostics))

    def test_ppp_profile_set(self):
        r = model("/ppp profile set ppp local-address=193.16.0.12")
        self.assertEqual(r.ppp_local_addresses["ppp"], "193.16.0.12")

    def test_radius_duration_and_secret_exclusion(self):
        r = model("/radius add address=192.0.2.9 timeout=2s secret=DO-NOT-LEAK")
        self.assertEqual(r.radius[0].timeout_ms, 2000)
        self.assertNotIn("DO-NOT-LEAK", json.dumps(r.to_dict()))

    def test_arbitrary_script_unresolved(self):
        r = model(":foreach x in=[/ip address find] do={ /ip address remove $x }")
        self.assertTrue(r.diagnostics)
        with self.assertRaises(UnsupportedExport):
            export_router(r, "routeros", "7.19")


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.r = Router("switch-X1", "switch", identity="switch-X1")
        self.r.firewall_v4.groups = [AddressGroup("snmp", "198.51.100.9")]
        self.r.firewall_v4.rules = [
            FirewallRule(
                "input", "accept", "udp", source_group="snmp", destination_ports="161"
            ),
            FirewallRule("input", "drop"),
        ]

    def test_snmp_poller_and_other_source(self):
        self.assertEqual(input_decision(self.r, "198.51.100.9"), "accept")
        self.assertEqual(input_decision(self.r, "198.51.100.10"), "drop")

    def test_drop_before_allow(self):
        self.r.firewall_v4.rules.reverse()
        self.assertEqual(input_decision(self.r, "198.51.100.9"), "drop")

    def test_disabled_allow_does_not_pass(self):
        self.r.firewall_v4.rules[0].enabled = False
        self.assertEqual(input_decision(self.r, "198.51.100.9"), "drop")

    def test_disabled_final_drop(self):
        self.r.firewall_v4.rules[-1].enabled = False
        self.assertTrue(
            any(f.check == "firewall.input-final-drop" for f in audit([self.r], {}))
        )

    def test_extra_matcher_not_unconditional(self):
        self.r.firewall_v4.rules[-1].extra = {"connection-state": "invalid"}
        self.assertFalse(self.r.firewall_v4.rules[-1].unconditional)
        self.assertTrue(
            any(f.check == "firewall.input-final-drop" for f in audit([self.r], {}))
        )

    def test_missing_group(self):
        self.r.firewall_v4.groups = []
        self.assertEqual(input_decision(self.r, "198.51.100.9"), "drop")

    def test_negated_unresolved_network_stays_unknown(self):
        from semanticrouter.evaluation import network_contains

        self.assertIsNone(network_contains("!poller.example", "198.51.100.9"))

    def test_numeric_tcp_protocol_does_not_accept_icmp(self):
        self.r.firewall_v4.rules[0].protocol = "6"
        self.assertEqual(
            input_decision(self.r, "198.51.100.9", protocol="icmp"), "drop"
        )

    def test_dns_group_is_unknown(self):
        self.r.firewall_v4.groups[0].network = "poller.example"
        self.assertEqual(input_decision(self.r, "198.51.100.9"), "unknown")

    def test_unknown_condition_is_not_pass(self):
        self.r.firewall_v4.rules[0].extra = {"connection-state": "new"}
        self.assertEqual(input_decision(self.r, "198.51.100.9"), "unknown")

    def test_unknown_allow_then_definite_allow_converges(self):
        self.r.firewall_v4.rules.insert(
            0, FirewallRule("input", "accept", ingress="ether1")
        )
        self.assertEqual(input_decision(self.r, "198.51.100.9"), "accept")

    def test_bond_policy(self):
        self.r.interfaces = [Interface("bond-uplink", "bonding")]
        self.assertTrue(any(f.check == "bond.mode" for f in audit([self.r], {})))

    def test_route_rule_order_disabled_unknown(self):
        r = model(
            '/routing filter rule add chain=OUT rule="if (dst == 0.0.0.0/0) { accept; }"\n/routing filter rule add chain=OUT rule=reject'
        )
        self.assertTrue(default_only(r, "OUT"))
        self.assertEqual(route_decision(r, "OUT", "203.0.113.1/32"), "reject")
        r.bgp.policies[0].supported = False
        self.assertEqual(route_decision(r, "OUT", "0.0.0.0/0"), "unknown")

    def test_border_customer_leak(self):
        r = model(
            '/routing filter rule add chain=OUT rule="if (dst == 0.0.0.0/0) { accept; }"\n/routing filter rule add chain=OUT comment="delete me" rule="if (dst in 203.0.113.0/24 && dst-len > 24) { accept; }"\n/routing filter rule add chain=OUT rule=reject'
        )
        self.assertFalse(default_only(r, "OUT"))

    def test_reciprocal_mesh_matches_addresses_not_names(self):
        bng = model(
            "/ip address add address=193.16.0.12 interface=loopback0\n/ip address add address=193.16.0.51 interface=to-border-X network=193.16.0.50\n/routing bgp connection add name=unhelpful-name remote.address=193.16.0.50 local.address=193.16.0.51"
        )
        border = model(
            "/ip address add address=193.16.0.50 interface=to-bng network=193.16.0.51\n/routing bgp connection add name=gw-X1 remote.address=193.16.0.51 local.address=193.16.0.50",
            name="border-X",
        )
        self.assertFalse(
            any(
                f.check in ("bng.mesh", "bng.mesh-reciprocal")
                for f in audit([bng, border], {"borders": ["border-X"]})
            )
        )
        border.bgp.peers[0].enabled = False
        self.assertTrue(
            any(
                f.check == "bng.mesh-reciprocal"
                for f in audit([bng, border], {"borders": ["border-X"]})
            )
        )


class ExportTests(unittest.TestCase):
    def test_ros6_semantics_and_ros7_export(self):
        r = load(Path(__file__).parent / "fixtures/routeros6.rsc")
        self.assertEqual(r.platform.version, "6.49.10")
        self.assertEqual(r.bgp.peers[0].local_as, "64512")
        self.assertEqual(r.bgp.peers[0].redistribute, ["connected"])
        self.assertEqual(route_decision(r, "TO-BORDER", "203.0.113.1/32"), "accept")
        output = export_router(r, "routeros", "7.19.3")
        self.assertTrue(output.complete)
        converted = model(output.text, "7.19.3")
        self.assertEqual(converted.bgp.peers[0].remote_as, "64512")
        self.assertEqual(converted.bgp.peers[0].redistribute, ["connected"])
        self.assertEqual(input_decision(converted, "198.51.100.9"), "accept")
        self.assertEqual(
            route_decision(converted, "TO-BORDER", "203.0.113.1/32"), "accept"
        )
        self.assertEqual(
            route_decision(converted, "TO-BORDER", "203.0.113.0/24"), "reject"
        )

    def test_unknown_feature_blocks_full_export(self):
        r = model("/interface wireguard add name=wg private-key=DO-NOT-LEAK")
        with self.assertRaises(UnsupportedExport):
            export_router(r, "routeros", "7.19")
        result = export_router(r, "routeros", "7.19", True)
        self.assertFalse(result.complete)
        self.assertIn("PARTIAL", result.text)
        self.assertNotIn("DO-NOT-LEAK", result.text)

    def test_unsupported_property_blocks_full_export(self):
        r = model("/ip dns set servers=1.1.1.1 allow-remote-requests=yes")
        with self.assertRaises(UnsupportedExport):
            export_router(r, "routeros", "7.19")

    def test_unresolved_selector_blocks_full_export(self):
        r = model('/ip firewall filter set [ find comment="x" ] disabled=no')
        with self.assertRaises(UnsupportedExport):
            export_router(r, "routeros", "7.19")

    def test_unsupported_target_version(self):
        for v in ("6.49", "7", "7.20", "8.1"):
            with self.subTest(v=v), self.assertRaises(UnsupportedExport):
                export_router(Router("r", "edge"), "routeros", v)

    def test_ios_supported_acl_fragment(self):
        r = model(
            "/system identity set name=example\n/ip firewall address-list add list=snmp address=198.51.100.9\n/ip firewall filter add chain=input action=accept protocol=udp dst-port=161 src-address-list=snmp\n/ip firewall filter add chain=input action=drop"
        )
        result = export_router(r, "cisco-ios", "15.2")
        self.assertIn("permit udp host 198.51.100.9 any eq 161", result.text)
        self.assertIn("deny ip any any", result.text)
        self.assertIn("attachment explicitly", result.text)

    def test_ios_rejects_unsupported_firewall_conditions(self):
        r = Router("r", "edge")
        r.firewall_v4.rules = [FirewallRule("input", "accept", ingress="mgmt")]
        with self.assertRaises(UnsupportedExport):
            export_router(r, "cisco-ios", "15.2")

    def test_ios_does_not_drop_intersecting_source_predicate(self):
        r = Router("r", "edge")
        r.firewall_v4.groups = [AddressGroup("trusted", "198.51.100.0/24")]
        r.firewall_v4.rules = [
            FirewallRule(
                "input", "accept", source_network="198.51.100.1", source_group="trusted"
            )
        ]
        with self.assertRaises(UnsupportedExport):
            export_router(r, "cisco-ios", "15.2")

    def test_ios_preserves_routeros_fallthrough(self):
        r = model("/ip firewall filter add chain=input action=accept protocol=icmp")
        result = export_router(r, "cisco-ios", "15.2")
        self.assertIn(" permit ip any any", result.text)

    def test_ios_bgp_never_silently_omitted(self):
        with self.assertRaises(UnsupportedExport):
            export_router(
                load(Path(__file__).parent / "fixtures/routeros6.rsc"),
                "cisco-ios",
                "15.2",
            )

    def test_inactive_bgp_definitions_not_silently_dropped(self):
        r = model("/routing bgp instance add name=unused as=64512", version="7.19")
        with self.assertRaises(UnsupportedExport):
            export_router(r, "routeros", "7.19")

    def test_fetch_script_does_not_look_like_empty_config(self):
        r = model("/tool fetch url=https://example.invalid/config")
        with self.assertRaises(UnsupportedExport):
            export_router(r, "routeros", "7.19")

    def test_ros6_implicit_accept_blocks_migration(self):
        r = model(
            "/routing filter add chain=OUT prefix=203.0.113.0/24 action=accept",
            version="6.4",
        )
        self.assertEqual(route_decision(r, "OUT", "198.51.100.1/32"), "accept")
        with self.assertRaises(UnsupportedExport):
            export_router(r, "routeros", "7.19")

    def test_ios_dns_value_must_be_ip(self):
        r = Router("r", "edge", dns=["1.1.1.1\nusername injected"])
        with self.assertRaises(UnsupportedExport):
            export_router(r, "cisco-ios", "15.2")

    def test_cli_partial_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "router.cfg"
            p.write_text("/interface bridge add name=bridge")
            self.assertEqual(
                main(
                    [
                        "export",
                        str(p),
                        "--vendor",
                        "routeros",
                        "--version",
                        "7.19",
                        "--allow-partial",
                        "--output",
                        str(Path(d) / "out.rsc"),
                    ]
                ),
                2,
            )


if __name__ == "__main__":
    unittest.main()
