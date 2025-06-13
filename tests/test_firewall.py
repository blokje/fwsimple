import unittest
from unittest import mock
import configparser
import tempfile
import os
import shutil
import sys # <--- Add this line

# Adjust path to import fwsimple
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fwsimple.firewall import Firewall
from fwsimple import constants
from fwsimple.zone import Zone, ZoneExpression
from fwsimple.rules.filter import Filter

# Ensure mockengine is available for test_firewall.py
if 'mockengine' not in constants.EXEC_MAP:
    constants.EXEC_MAP['mockengine'] = 99 # Assign a dummy integer ID

# Mock Engine for Firewall tests
class MockEngine:
    def __init__(self, firewall_instance):
        self.firewall = firewall_instance
        self.committed = False

    def commit(self):
        self.committed = True

    def apply(self): # Just in case it's called, though commit is primary
        return []

class TestFirewall(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.rules_dir = os.path.join(self.temp_dir, 'rules')
        os.makedirs(self.rules_dir)

        # Mock fwsimple.engines.load_engine to return our MockEngine
        self.load_engine_patcher = mock.patch('fwsimple.engines.load_engine')
        self.mock_load_engine = self.load_engine_patcher.start()
        self.mock_load_engine.return_value = MockEngine

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        self.load_engine_patcher.stop()

    def _create_config_file(self, content, filename="fwsimple.cfg"):
        path = os.path.join(self.temp_dir, filename)
        with open(path, 'w') as f:
            f.write(content)
        return path

    def _create_rule_file(self, content, filename="test.rule"):
        path = os.path.join(self.rules_dir, filename)
        with open(path, 'w') as f:
            f.write(content)
        return path

    def test_firewall_init_load_config_ok(self):
        config_content = """
[fwsimple]
rulesets = {rules_dir}
engine = mockengine
[policy]
in = accept
out = drop
forward = reject
[zones]
lan = eth0
wan = eth1:192.168.1.0/24
""".format(rules_dir=self.rules_dir)
        config_path = self._create_config_file(config_content)

        fw = Firewall(configfile=config_path)

        self.assertEqual(fw.ruleset_location, self.rules_dir)
        self.assertEqual(fw.exec_type, constants.EXEC_MAP['mockengine']) # Assuming mockengine is added to EXEC_MAP for test
        self.assertIsInstance(fw.engine, MockEngine)
        self.mock_load_engine.assert_called_once_with('mockengine')

    def test_firewall_load_config_invalid_engine(self):
        config_content = """
[fwsimple]
rulesets = {rules_dir}
engine = non_existent_engine
[policy]
in = accept
[zones]
lan = eth0
""".format(rules_dir=self.rules_dir)
        config_path = self._create_config_file(config_content)
        # Temporarily break the mock for this specific test if EXEC_MAP check happens first
        self.mock_load_engine.side_effect = KeyError("Unsupported engine!")
        # Or, if EXEC_MAP itself would raise KeyError:
        # constants.EXEC_MAP.pop('non_existent_engine', None) # Ensure it's not there

        with mock.patch.dict(constants.EXEC_MAP, {}, clear=True): # Ensure engine not in EXEC_MAP
             with self.assertRaisesRegex(Exception, "Unsupported engine!"):
                Firewall(configfile=config_path)


    def test_firewall_load_zones(self):
        config_content = """
[fwsimple]
rulesets = {rules_dir}
engine = mockengine
[policy]
in = accept
[zones]
lan = eth0:10.0.0.0/24,eth1
dmz = ppp0
""".format(rules_dir=self.rules_dir)
        config_path = self._create_config_file(config_content)
        fw = Firewall(configfile=config_path)

        self.assertTrue(fw.has_zone(constants.GLOBAL_ZONE_NAME))
        self.assertTrue(fw.has_zone("lan"))
        self.assertTrue(fw.has_zone("dmz"))
        self.assertFalse(fw.has_zone("wan"))

        lan_zone = fw.get_zone("lan")
        self.assertIsNotNone(lan_zone)
        self.assertEqual(len(lan_zone.expressions), 2) # eth0:10.0.0.0/24 and eth1

    def test_firewall_has_zone_expression(self):
        config_content = """
[fwsimple]
rulesets = {rules_dir}
engine = mockengine
[policy]
in = accept
[zones]
lan = eth0:10.0.0.0/24
""".format(rules_dir=self.rules_dir)
        config_path = self._create_config_file(config_content)
        fw = Firewall(configfile=config_path)

        # Create a ZoneExpression to test against (needs a dummy zone for init)
        dummy_zone_for_expr = Zone(fw, "dummy", "eth0:10.0.0.0/24")
        expr_to_find = dummy_zone_for_expr.expressions[0]

        self.assertTrue(fw.has_zone_expression(expr_to_find))

        dummy_zone_for_expr_new = Zone(fw, "dummy2", "ppp0")
        expr_not_to_find = dummy_zone_for_expr_new.expressions[0]
        self.assertFalse(fw.has_zone_expression(expr_not_to_find))


    def test_firewall_parse_ruleset(self):
        rule_content = """
[allow_ssh]
zone = lan
source = 192.168.1.50
port = 22
action = accept
direction = in

[drop_all_else]
zone = lan
action = drop
direction = in
"""
        self._create_rule_file(rule_content, "myrules.rule")

        config_content = """
[fwsimple]
rulesets = {rules_dir}
engine = mockengine
[policy]
in = reject
[zones]
lan = eth0
""".format(rules_dir=self.rules_dir)
        config_path = self._create_config_file(config_content)
        fw = Firewall(configfile=config_path) # load_rulesets is called in init

        self.assertEqual(len(fw.rules), 2)
        rule_names = [r.name for r in fw.rules]
        self.assertIn("myrules.rule::allow_ssh", rule_names)
        self.assertIn("myrules.rule::drop_all_else", rule_names)

        ssh_rule = next(r for r in fw.rules if r.name == "myrules.rule::allow_ssh")
        self.assertEqual(ssh_rule.action, "accept")
        self.assertEqual(ssh_rule.port, ["22"])

    def test_firewall_parse_ruleset_error_in_rule(self):
        rule_content = """
[bad_rule]
zone = lan
action = super_accept ; invalid action
"""
        self._create_rule_file(rule_content, "bad.rule")
        config_content = """
[fwsimple]
rulesets = {rules_dir}
engine = mockengine
[policy]
in = reject
[zones]
lan = eth0
""".format(rules_dir=self.rules_dir)
        config_path = self._create_config_file(config_content)

        with self.assertRaisesRegex(Exception, "Error in bad.rule::bad_rule:.*action.*not understood"):
            Firewall(configfile=config_path)

    def test_get_default_policy(self):
        config_content = """
[fwsimple]
rulesets = {rules_dir}
engine = mockengine
[policy]
in = accept
out = reject
forward = discard
[zones]
lan = eth0
""".format(rules_dir=self.rules_dir)
        config_path = self._create_config_file(config_content)
        fw = Firewall(configfile=config_path)

        self.assertEqual(fw.get_default_policy("in"), "accept")
        self.assertEqual(fw.get_default_policy("out"), "reject")
        self.assertEqual(fw.get_default_policy("forward"), "discard")

    def test_get_default_policy_invalid(self):
        config_content = """
[fwsimple]
rulesets = {rules_dir}
engine = mockengine
[policy]
in = something_bad
[zones]
lan = eth0
""".format(rules_dir=self.rules_dir)
        config_path = self._create_config_file(config_content)
        fw = Firewall(configfile=config_path)
        with self.assertRaisesRegex(Exception, "Policy invalid 'something_bad' not allowed"):
            fw.get_default_policy("in")

    def test_firewall_commit(self):
        config_content = """
[fwsimple]
rulesets = {rules_dir}
engine = mockengine
[policy]
in = accept
[zones]
lan = eth0
""".format(rules_dir=self.rules_dir)
        config_path = self._create_config_file(config_content)
        fw = Firewall(configfile=config_path)
        fw.commit()
        self.assertTrue(fw.engine.committed)


if __name__ == '__main__':
    # Add mockengine to EXEC_MAP for tests to run standalone
    if 'mockengine' not in constants.EXEC_MAP:
        constants.EXEC_MAP['mockengine'] = 99 # Assign a dummy int value
    unittest.main()
