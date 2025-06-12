import io
import os
import shutil
import sys
import tempfile
import unittest
from typing import Dict, List

# Adjust path to import fwsimple from the parent directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from fwsimple.firewall import Firewall
from fwsimple import constants
from tests.test_helper import EngineTestCaseBase

class IptablesTestCase(EngineTestCaseBase):
    engine_name_for_firewall_init = 'iptables'

    def _normalize_command(self, cmd_str: str) -> str:
        # iptables specific normalization
        return cmd_str.replace("iptables ", "", 1).replace("ip6tables ", "", 1).strip()

    def _process_dry_run_output(self, output_lines: List[str]) -> List[str]:
        # For iptables, filter out empty lines (done by base) and comments
        processed_lines = []
        for line in output_lines:
            stripped_line = line.strip()
            if stripped_line and not stripped_line.startswith('#'):
                processed_lines.append(stripped_line)
        return processed_lines

class TestIptablesEngineBasic(IptablesTestCase):

    def test_basic_init_and_default_policies(self):
        config_content = """
[fwsimple]
rulesets = %%RULESETS_DIR%%
engine = iptables

[policy]
in = reject
out = accept
forward = drop

[zones]
; No specific zones, only global should be created for iptables (less explicit than nftables)
"""
        rules_files: Dict[str, str] = {}

        # Expected commands for iptables. Note: This is a simplified initial set.
        # Actual commands will depend on the specific implementation details of the iptables engine.
        # This will likely need significant refinement.
        expected_commands = [
            # IPv4 commands
            "iptables -P INPUT ACCEPT", # Initial policy before dropping/rejecting
            "iptables -P FORWARD ACCEPT",
            "iptables -P OUTPUT ACCEPT",
            "iptables -F INPUT",
            "iptables -F FORWARD",
            "iptables -F OUTPUT",
            "iptables -X", # Delete non-default chains
            "iptables -Z", # Zero counters
            "iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A OUTPUT -o lo -j ACCEPT",
            "iptables -A INPUT -m state --state INVALID -j DROP",
            "iptables -A FORWARD -m state --state INVALID -j DROP",
            # ICMP rules (example, may vary)
            "iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT",
            # Default policies applied at the end
            "iptables -P INPUT REJECT",
            "iptables -P FORWARD DROP",
            "iptables -P OUTPUT ACCEPT",

            # IPv6 commands (ip6tables)
            "ip6tables -P INPUT ACCEPT",
            "ip6tables -P FORWARD ACCEPT",
            "ip6tables -P OUTPUT ACCEPT",
            "ip6tables -F INPUT",
            "ip6tables -F FORWARD",
            "ip6tables -F OUTPUT",
            "ip6tables -X",
            "ip6tables -Z",
            "ip6tables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "ip6tables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "ip6tables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "ip6tables -A INPUT -i lo -j ACCEPT",
            "ip6tables -A OUTPUT -o lo -j ACCEPT",
            "ip6tables -A INPUT -m state --state INVALID -j DROP",
            "ip6tables -A FORWARD -m state --state INVALID -j DROP",
            # ICMPv6 rules (example, may vary)
            "ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request -j ACCEPT",
            # Default policies applied at the end for IPv6
            "ip6tables -P INPUT REJECT",
            "ip6tables -P FORWARD DROP",
            "ip6tables -P OUTPUT ACCEPT",
        ]

        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

if __name__ == '__main__':
    unittest.main()
