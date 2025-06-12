import unittest
import sys
import os
import ipaddress

# Adjust path to import fwsimple
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fwsimple import zone, constants
from fwsimple.firewall import Firewall # Needed for Zone/ZoneExpression instantiation

# Mock Firewall class for testing purposes
class MockFirewall:
    def __init__(self):
        self._zone_expressions = []

    def has_zone_expression(self, ZExpression):
        # Simplified mock: real implementation might be more complex
        if ZExpression in self._zone_expressions:
            return True
        self._zone_expressions.append(ZExpression)
        return False

class TestZoneExpression(unittest.TestCase):
    def setUp(self):
        self.mock_firewall = MockFirewall()
        # Dummy zone object for ZoneExpression, as it requires a Zone instance
        self.dummy_zone = zone.Zone(self.mock_firewall, "dummy_zone_name", None)

    def test_expression_interface_only(self):
        expr = zone.ZoneExpression(self.mock_firewall, self.dummy_zone, "eth0")
        self.assertEqual(expr.interface, "eth0")
        self.assertIsNone(expr.source)
        self.assertEqual(expr.proto, constants.PROTO_IPV4 + constants.PROTO_IPV6)
        self.assertFalse(expr.specific)

    def test_expression_ipv4(self):
        expr = zone.ZoneExpression(self.mock_firewall, self.dummy_zone, "eth1:192.168.1.0/24")
        self.assertEqual(expr.interface, "eth1")
        self.assertEqual(expr.source, ipaddress.ip_network("192.168.1.0/24"))
        self.assertEqual(expr.proto, constants.PROTO_IPV4)
        self.assertTrue(expr.specific)

    def test_expression_ipv6(self):
        expr = zone.ZoneExpression(self.mock_firewall, self.dummy_zone, "eth2:2001:db8::/32")
        self.assertEqual(expr.interface, "eth2")
        self.assertEqual(expr.source, ipaddress.ip_network("2001:db8::/32"))
        self.assertEqual(expr.proto, constants.PROTO_IPV6)
        self.assertTrue(expr.specific)

    def test_repr(self):
        expr = zone.ZoneExpression(self.mock_firewall, self.dummy_zone, "eth0")
        self.assertTrue(repr(expr).startswith("<ZoneExpression"))

    def test_equality(self):
        expr1 = zone.ZoneExpression(self.mock_firewall, self.dummy_zone, "eth0")
        expr2 = zone.ZoneExpression(self.mock_firewall, self.dummy_zone, "eth0")
        expr3 = zone.ZoneExpression(self.mock_firewall, self.dummy_zone, "eth1")
        expr4 = zone.ZoneExpression(self.mock_firewall, self.dummy_zone, "eth0:10.0.0.0/8")

        self.assertEqual(expr1, expr2)
        self.assertNotEqual(expr1, expr3)
        self.assertNotEqual(expr1, expr4)
        self.assertNotEqual(expr1, "not_an_expression")

    def test_comparison_specific_vs_generic(self):
        # specific (source defined) should be "less than" generic (no source) for sorting,
        # but current __lt__ makes specific > generic if not global.
        # The logic is: if self.source, it's true (smaller), unless other.source also exists.
        # if self.source and other.source: based on num_addresses
        # if self.source (and other is not): self is smaller (True)
        # if other.source (and self is not): self is larger (False)
        # if neither has source: False (equal in this regard)

        generic_expr = zone.ZoneExpression(self.mock_firewall, self.dummy_zone, "eth0") # specific = False
        specific_expr = zone.ZoneExpression(self.mock_firewall, self.dummy_zone, "eth0:10.0.0.0/8") # specific = True

        # According to ZoneExpression.__lt__
        # if self.source: return True (smaller)
        # Therefore, specific_expr < generic_expr should be True
        self.assertTrue(specific_expr < generic_expr, "Specific should be less than generic")
        self.assertFalse(generic_expr < specific_expr, "Generic should not be less than specific")

    def test_comparison_by_network_size(self):
        smaller_net_expr = zone.ZoneExpression(self.mock_firewall, self.dummy_zone, "eth0:10.0.0.0/24") # smaller network
        larger_net_expr = zone.ZoneExpression(self.mock_firewall, self.dummy_zone, "eth0:10.0.0.0/8") # larger network

        # self.source.num_addresses < other.source.num_addresses
        self.assertTrue(smaller_net_expr < larger_net_expr, "Smaller network should be less than larger network")
        self.assertFalse(larger_net_expr < smaller_net_expr, "Larger network should not be less than smaller network")

    def test_comparison_with_global_zone(self):
        # Global zone expressions are special.
        # A ZoneExpression needs a Zone. Let's create zones.
        global_zone_obj = zone.Zone(self.mock_firewall, constants.GLOBAL_ZONE_NAME, "eth0")
        # The expression itself doesn't store global status, its parent zone does.
        # The __lt__ method uses self._zone.name

        global_expr = global_zone_obj.expressions[0] # Get the ZoneExpression from the global zone

        other_zone = zone.Zone(self.mock_firewall, "myzone", "eth1:10.0.0.0/24")
        other_expr = other_zone.expressions[0]

        # if self._zone.name == constants.GLOBAL_ZONE_NAME: return True
        self.assertTrue(global_expr < other_expr, "Global expression should be less than other")
        # if other._zone.name == constants.GLOBAL_ZONE_NAME: return False
        self.assertFalse(other_expr < global_expr, "Other expression should not be less than global")


class TestZone(unittest.TestCase):
    def setUp(self):
        self.mock_firewall = MockFirewall()

    def test_zone_creation_no_expressions(self):
        z = zone.Zone(self.mock_firewall, "myzone", None)
        self.assertEqual(z.name, "myzone")
        self.assertEqual(len(z.expressions), 0)

    def test_zone_creation_single_expression(self):
        z = zone.Zone(self.mock_firewall, "myzone", "eth0")
        self.assertEqual(z.name, "myzone")
        self.assertEqual(len(z.expressions), 1)
        self.assertEqual(z.expressions[0].interface, "eth0")

    def test_zone_creation_multiple_expressions(self):
        z = zone.Zone(self.mock_firewall, "dmz", "eth1:10.0.0.0/24,eth2:10.0.1.0/24")
        self.assertEqual(z.name, "dmz")
        self.assertEqual(len(z.expressions), 2)
        self.assertEqual(z.expressions[0].interface, "eth1")
        self.assertEqual(z.expressions[0].source, ipaddress.ip_network("10.0.0.0/24"))
        self.assertEqual(z.expressions[1].interface, "eth2")
        self.assertEqual(z.expressions[1].source, ipaddress.ip_network("10.0.1.0/24"))

    def test_zone_add_expression_duplicate_warning(self):
        # Reset mock_firewall expressions for this test
        self.mock_firewall._zone_expressions = []

        z = zone.Zone(self.mock_firewall, "testzone", "eth0") # First eth0 added to firewall tracker
        with self.assertWarns(Warning) as cm:
            z.add_expression("eth0") # Adding the same expression again
        self.assertTrue("Duplicate zone definition detected" in str(cm.warning))
        # Should still add it, as the check is a warning, not prevention in current code
        self.assertEqual(len(z.expressions), 2)


    def test_repr(self):
        z = zone.Zone(self.mock_firewall, "myzone", "eth0")
        self.assertTrue(repr(z).startswith("<Zone"))


if __name__ == '__main__':
    unittest.main()
