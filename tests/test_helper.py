import unittest
import tempfile
import os
import shutil
import io
import sys
from typing import Dict, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from fwsimple.firewall import Firewall

class EngineTestCaseBase(unittest.TestCase):
    default_engine_in_config = 'OVERRIDE_ME_IN_SUBCLASS' # e.g., 'nftables' or 'iptables'

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.rules_dir = os.path.join(self.temp_dir, 'rules')
        os.makedirs(self.rules_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _get_engine_specific_firewall_args(self) -> Dict:
        """
        Returns engine-specific arguments for Firewall constructor.
        Currently, no engine-specific args are passed directly to __init__.
        Engine is determined by config file content.
        """
        return {}

    def _process_dry_run_output(self, output_lines: List[str]) -> List[str]:
        return [line for line in output_lines if line.strip()]

    def _run_fwsimple_dry_run(self, config_content: str, rules_files: Dict[str, str]) -> List[str]:
        config_file_path = os.path.join(self.temp_dir, 'test_fwsimple.cfg')
        # Ensure rules_dir is correctly substituted.
        config_content_processed = config_content.replace('%%RULESETS_DIR%%', self.rules_dir)

        # Substitute engine placeholder if present
        config_content_processed = config_content_processed.replace('%%ENGINE_TYPE%%', self.default_engine_in_config)

        with open(config_file_path, 'w') as f:
            f.write(config_content_processed)

        for file_name, content in rules_files.items():
            with open(os.path.join(self.rules_dir, file_name), 'w') as f:
                f.write(content)

        old_stdout = sys.stdout
        sys.stdout = captured_stdout = io.StringIO()

        try:
            firewall_args = {'configfile': config_file_path, 'dry_run': True}
            firewall_args.update(self._get_engine_specific_firewall_args())
            fw = Firewall(**firewall_args)
            fw.commit()
        finally:
            sys.stdout = old_stdout

        output = captured_stdout.getvalue().strip()
        if not output:
            return []

        processed_output = self._process_dry_run_output(output.splitlines())
        return processed_output

    def _normalize_command(self, cmd_str: str) -> str:
        raise NotImplementedError("Subclasses must implement _normalize_command")

    def assert_commands_equal(self, actual_commands: List[str], expected_commands: List[str]):
        actual_normalized = [self._normalize_command(cmd) for cmd in actual_commands]
        expected_normalized = [self._normalize_command(cmd) for cmd in expected_commands]

        self.assertEqual(len(actual_normalized), len(expected_normalized),
                         "Number of commands differ.\nActual: {0}\nExpected: {1}".format(actual_normalized, expected_normalized))

        for i, actual_cmd in enumerate(actual_normalized):
            self.assertEqual(actual_cmd, expected_normalized[i],
                             "Command {0} differs.\nActual:   {1}\nExpected: {2}\n\nFull Actual:\n{3}\n\nFull Expected:\n{4}".format(i+1, actual_cmd, expected_normalized[i], actual_normalized, expected_normalized))

    # --- Scenario Helper Methods ---

    def _get_config_basic_init(self) -> str:
        """Scenario 1: Basic initialization, default policies, no rules, global zone only."""
        return """
[fwsimple]
rulesets = %%RULESETS_DIR%%
engine = %%ENGINE_TYPE%%
[policy]
in = reject
out = accept
forward = drop
[zones]
; No specific zones, global is implicit
"""

    def _get_config_one_zone(self, zone_name="lan", zone_def="eth0") -> str:
        """Common config part for scenarios needing one defined zone."""
        return """
[fwsimple]
rulesets = %%RULESETS_DIR%%
engine = %%ENGINE_TYPE%%
[policy]
in = reject
out = accept
forward = drop
[zones]
{zone_name} = {zone_def}
""".format(zone_name=zone_name, zone_def=zone_def)

    def _get_rules_tcp_allow(self, zone_name="lan", port="22", source="192.168.1.100/32") -> Dict[str, str]:
        """Scenario 2: Simple TCP Allow Rule."""
        return {
            "tcp_allow.rule": """
[allow_ssh_from_host]
zone = {zone_name}
direction = in
protocol = tcp
port = {port}
source = {source}
action = accept
""".format(zone_name=zone_name, port=port, source=source)
        }

    def _get_rules_udp_deny(self, zone_name="lan", port="53", destination="8.8.8.8/32", action="discard") -> Dict[str, str]:
        """Scenario 3: Simple UDP Deny Rule."""
        return {
            "udp_deny.rule": """
[deny_dns_to_external]
zone = {zone_name}
direction = out
protocol = udp
port = {port}
destination = {destination}
action = {action}
""".format(zone_name=zone_name, port=port, destination=destination, action=action)
        }

    def _get_rules_logged_rule(self, zone_name="lan", port="22", source="192.168.1.100/32", action="accept") -> Dict[str, str]:
        """Scenario 4: Rule with Logging."""
        rule_content = """
[logged_ssh_rule]
zone = {zone_name}
direction = in
protocol = tcp
port = {port}
action = {action}
log = true
""".format(zone_name=zone_name, port=port, action=action)

        if source and source.lower() != "any":
            rule_content += "\nsource = {0}".format(source)

        return {
            "logged_rule.rule": rule_content
        }

    def _get_rules_multiple_ports(self, zone_name="lan", ports="80,443,8080", action="accept") -> Dict[str, str]:
        """Scenario 5: Rule with Multiple Ports."""
        return {
            "multi_port.rule": """
[allow_web_ports]
zone = {zone_name}
direction = in
protocol = tcp
port = {ports}
action = {action}
""".format(zone_name=zone_name, ports=ports, action=action)
        }

    def _get_rules_port_range(self, zone_name="lan", port_range="1000-1024", action="accept") -> Dict[str, str]:
        """Scenario 6: Rule with Port Range."""
        return {
            "port_range.rule": """
[allow_custom_range]
zone = {zone_name}
direction = in
protocol = tcp
port = {port_range}
action = {action}
""".format(zone_name=zone_name, port_range=port_range, action=action)
        }

    def _get_rules_ipv6_source_allow(self, zone_name="lan", port="22", source="2001:db8:cafe::100/128") -> Dict[str, str]:
        """Scenario 7: IPv6 Rule (source)."""
        return {
            "ipv6_allow.rule": """
[allow_ipv6_ssh]
zone = {zone_name}
direction = in
protocol = tcp
port = {port}
source = {source}
action = accept
""".format(zone_name=zone_name, port=port, source=source)
        }

    def _get_config_multiple_zones(self) -> str:
        """Scenario 8: Multiple Zones defined for zone expression generation testing."""
        return """
[fwsimple]
rulesets = %%RULESETS_DIR%%
engine = %%ENGINE_TYPE%%
[policy]
in = discard
out = accept
forward = discard
[zones]
public = eth0
private_lan = eth1:192.168.1.0/24
guest_wifi = eth1:192.168.2.0/24
vpn_users = tun0
dmz_ipv6 = eth2:2001:db8:d320::/64
"""
