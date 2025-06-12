import unittest
import sys
import os
import ipaddress

# Adjust path to import fwsimple
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fwsimple.rules import filter as fw_filter
from fwsimple import constants

# Mock Firewall class for testing Filter rule instantiation
class MockFirewall:
    def __init__(self, valid_zones=None):
        self._valid_zones = valid_zones if valid_zones is not None else ['testzone']

    def has_zone(self, zone_name):
        return zone_name in self._valid_zones

class TestFilterRule(unittest.TestCase):
    def setUp(self):
        self.mock_firewall = MockFirewall(valid_zones=['lan', 'wan', 'dmz'])

    def test_filter_creation_basic(self):
        rule = fw_filter.Filter(name="allow_ssh", firewall=self.mock_firewall, zone="lan",
                                source="192.168.1.100", destination="10.0.0.5",
                                port="22", protocol="tcp", action="accept", log=True, direction="in")
        self.assertEqual(rule.name, "allow_ssh")
        self.assertEqual(rule.zone, "lan")
        self.assertEqual(rule.source, [ipaddress.ip_network("192.168.1.100")])
        self.assertEqual(rule.destination, [ipaddress.ip_network("10.0.0.5")])
        self.assertEqual(rule.port, ["22"])
        self.assertEqual(rule.protocol, "tcp")
        self.assertEqual(rule.action, "accept")
        self.assertTrue(rule.log)
        self.assertEqual(rule.direction, "in")

    def test_filter_invalid_zone(self):
        with self.assertRaises(Warning): # Current code raises Warning, not Exception
            fw_filter.Filter(name="bad_zone_rule", firewall=self.mock_firewall, zone="unknownzone")

    def test_filter_set_source_multiple(self):
        rule = fw_filter.Filter(name="multi_source", firewall=self.mock_firewall, zone="lan")
        rule.set_source("192.168.1.1, 2001:db8::1")
        self.assertIn(ipaddress.ip_network("192.168.1.1"), rule.source)
        self.assertIn(ipaddress.ip_network("2001:db8::1"), rule.source)

    def test_filter_set_destination_none(self):
        rule = fw_filter.Filter(name="no_dest", firewall=self.mock_firewall, zone="lan")
        rule.set_destination(None)
        self.assertIsNone(rule.destination)

    def test_filter_set_port_multiple_and_range(self):
        rule = fw_filter.Filter(name="multi_port", firewall=self.mock_firewall, zone="lan")
        rule.set_port("80,443,1000-1024")
        self.assertEqual(rule.port, ["80", "443", "1000-1024"])

    def test_filter_invalid_action(self):
        with self.assertRaises(Exception) as cm:
            fw_filter.Filter(name="bad_action", firewall=self.mock_firewall, zone="lan", action="myaction")
        self.assertTrue("Action 'myaction' is not understood!" in str(cm.exception))

    def test_filter_invalid_direction(self):
        with self.assertRaises(Exception) as cm:
            fw_filter.Filter(name="bad_direction", firewall=self.mock_firewall, zone="lan", direction="sideways")
        self.assertTrue("Direction 'sideways' is not understood!" in str(cm.exception))

    def test_filter_set_country(self):
        rule = fw_filter.Filter(name="country_rule", firewall=self.mock_firewall, zone="wan")
        rule.set_country("US,CA")
        self.assertEqual(rule.country, "US,CA")
        rule.set_country(None)
        self.assertIsNone(rule.country)

    def test_multiport_property(self):
        rule = fw_filter.Filter(name="mp_test", firewall=self.mock_firewall, zone="lan")

        rule.set_port(None)
        self.assertFalse(rule.multiport, "None port should not be multiport")

        rule.set_port("80")
        self.assertFalse(rule.multiport, "Single port '80' should not be multiport")

        rule.set_port("22,23")
        self.assertTrue(rule.multiport, "Multiple ports '22,23' should be multiport")

        rule.set_port("1000-1024")
        self.assertTrue(rule.multiport, "Port range '1000-1024' should be multiport")

        rule.set_port("8080, 9000-9010") # A mix, first element not a range, but length > 1
        self.assertTrue(rule.multiport, "Mixed ports '8080, 9000-9010' should be multiport")


    def test_get_source_destinations(self):
        rule = fw_filter.Filter(name="src_dest_test", firewall=self.mock_firewall, zone="lan")

        # 1. No source, no destination
        rule.set_source(None)
        rule.set_destination(None)
        results = list(rule.get_source_destinations())
        self.assertEqual(results, [(None, None)])

        # 2. Source only (IPv4)
        s_ipv4 = "192.168.1.1"
        rule.set_source(s_ipv4)
        rule.set_destination(None)
        results = list(rule.get_source_destinations())
        self.assertEqual(results, [(ipaddress.ip_network(s_ipv4), None)])

        # 3. Destination only (IPv6)
        d_ipv6 = "2001:db8::1"
        rule.set_source(None)
        rule.set_destination(d_ipv6)
        results = list(rule.get_source_destinations())
        self.assertEqual(results, [(None, ipaddress.ip_network(d_ipv6))])

        # 4. Both source (IPv4, IPv6) and destination (IPv4, IPv6)
        s_ipv4_net = ipaddress.ip_network("10.0.0.0/24")
        s_ipv6_net = ipaddress.ip_network("2001:cafe::/32")
        d_ipv4_net = ipaddress.ip_network("172.16.0.0/16")
        d_ipv6_net = ipaddress.ip_network("2001:feed::/32")

        rule.set_source("{0},{1}".format(s_ipv4_net, s_ipv6_net))
        rule.set_destination("{0},{1}".format(d_ipv4_net, d_ipv6_net))

        expected_combinations = [
            (s_ipv4_net, d_ipv4_net), # IPv4 to IPv4
            (s_ipv6_net, d_ipv6_net)  # IPv6 to IPv6
            # IPv4 to IPv6 and IPv6 to IPv4 are correctly excluded by the method's logic
        ]
        results = list(rule.get_source_destinations())

        self.assertEqual(len(results), len(expected_combinations))
        for res_tuple in results:
            self.assertIn(res_tuple, expected_combinations)
        for exp_tuple in expected_combinations:
            self.assertIn(exp_tuple, results)

    def test_repr(self):
        rule = fw_filter.Filter(name="repr_test", firewall=self.mock_firewall, zone="lan")
        self.assertTrue(repr(rule).startswith("<rules.filter.Filter"))

if __name__ == '__main__':
    unittest.main()
