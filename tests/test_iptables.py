import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import Dict, List

# Adjust path to import fwsimple from the parent directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from fwsimple.firewall import Firewall
from fwsimple import constants

class IPTablesTestCase(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.rules_dir = os.path.join(self.temp_dir, 'rules')
        os.makedirs(self.rules_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _run_fwsimple_dry_run(self, config_content: str, rules_files: Dict[str, str]) -> List[str]:
        """
        Runs fwsimple with the given config and rules, captures dry-run output.
        """
        config_file_path = os.path.join(self.temp_dir, 'test_fwsimple.cfg')

        # Replace placeholder for ruleset directory in config
        config_content = config_content.replace('%%RULESETS_DIR%%', self.rules_dir)

        with open(config_file_path, 'w') as f:
            f.write(config_content)

        for file_name, content in rules_files.items():
            with open(os.path.join(self.rules_dir, file_name), 'w') as f:
                f.write(content)

        old_stdout = sys.stdout
        sys.stdout = captured_stdout = io.StringIO()

        try:
            fw = Firewall(configfile=config_file_path, dry_run=True)
            fw.commit()
        finally:
            sys.stdout = old_stdout

        output = captured_stdout.getvalue().strip()
        if not output:
            return []
        return output.splitlines()

    def assert_commands_equal(self, actual_commands: List[str], expected_commands: List[str]):
        # Normalize commands by removing potential iptables/ip6tables executable path if present
        # and stripping extra whitespace from each command string.
        normalize = lambda cmd_str: cmd_str.replace("iptables ", "", 1).replace("ip6tables ", "", 1).strip()

        actual_normalized = [normalize(cmd) for cmd in actual_commands]
        expected_normalized = [normalize(cmd) for cmd in expected_commands]

        self.assertEqual(len(actual_normalized), len(expected_normalized),
                         "Number of commands differ.\nActual: {}\nExpected: {}".format(actual_normalized, expected_normalized))

        for i, actual_cmd in enumerate(actual_normalized):
            self.assertEqual(actual_cmd, expected_normalized[i],
                             "Command {} differs.\nActual:   {}\nExpected: {}\n\nFull Actual:\n{}\n\nFull Expected:\n{}".format(i+1, actual_cmd, expected_normalized[i], actual_normalized, expected_normalized))


class TestIPTablesEngine(IPTablesTestCase):

    def test_case_1_basic_init_and_default_policies(self):
        config_content = """
[fwsimple]
rulesets = %%RULESETS_DIR%%
engine = iptables

[policy]
in = reject
out = accept
forward = discard

[zones]
; No specific zones, only global should be created
"""
        rules_files: Dict[str, str] = {} # No rule files

        # Expected commands will need to be replaced with IPTables equivalents
        expected_commands = [
            # Init commands (constants.BASIC_IPTABLES_INIT - 9 pairs = 18 commands)
            "iptables -F",
            "ip6tables -F",
            "iptables -X",
            "ip6tables -X",
            "iptables -Z",
            "ip6tables -Z",
            "iptables -A INPUT -i lo -j ACCEPT",
            "ip6tables -A INPUT -i lo -j ACCEPT",
            "iptables -A OUTPUT -o lo -j ACCEPT",
            "ip6tables -A OUTPUT -o lo -j ACCEPT",
            "iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "ip6tables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "ip6tables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "ip6tables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "iptables -A INPUT -m conntrack --ctstate INVALID -j DROP",
            "ip6tables -A INPUT -m conntrack --ctstate INVALID -j DROP",
            # BASIC_IP4TABLES_INIT for iptables (5 commands)
            "iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT -m comment --comment \"[ICMP] Echo Request\"",
            "iptables -A INPUT -p icmp -m icmp --icmp-type 3/4 -j ACCEPT -m comment --comment \"[ICMP] Fragmentation needed\"",
            "iptables -A INPUT -p icmp -m icmp --icmp-type 3/3 -j ACCEPT -m comment --comment \"[ICMP] Port unreachable\"",
            "iptables -A INPUT -p icmp -m icmp --icmp-type 3/1 -j ACCEPT -m comment --comment \"[ICMP] Host unreachable\"",
            "iptables -A INPUT -p icmp -m icmp --icmp-type 4 -j ACCEPT -m comment --comment \"[ICMP] Source Quench (RFC 792)\"",
            # BASIC_IP6TABLES_INIT for ip6tables
            "ip6tables -A INPUT -p 59 -j ACCEPT -m comment --comment \"[IPv6] No next header RFC2460\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 2 -j ACCEPT -m comment --comment \"[ICMPv6] Packet too big\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 3 -j ACCEPT -m comment --comment \"[ICMPv6] Time exceeded\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 133 -j ACCEPT -m comment --comment \"[ICMPv6] Router sollicitation\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 134 -j ACCEPT -m comment --comment \"[ICMPv6] Router advertisement\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 135 -j ACCEPT -m comment --comment \"[ICMPv6] Neighbor sollicitation\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 136 -j ACCEPT -m comment --comment \"[ICMPv6] Neighbor advertisement\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 128 -j ACCEPT -m comment --comment \"[ICMPv6] Echo Request\"",

            # Zone creation (global)
            "iptables -N IN_global",
            "ip6tables -N IN_global",
            "iptables -N OUT_global",
            "ip6tables -N OUT_global",
            "iptables -N FWD_global",
            "ip6tables -N FWD_global",

            # Zone expression creation (global)
            "iptables -A INPUT -m comment --comment \"Zone global\" -j IN_global",
            "ip6tables -A INPUT -m comment --comment \"Zone global\" -j IN_global",
            "iptables -A OUTPUT -m comment --comment \"Zone global\" -j OUT_global",
            "ip6tables -A OUTPUT -m comment --comment \"Zone global\" -j OUT_global",
            "iptables -A FORWARD -m comment --comment \"Zone global\" -j FWD_global",
            "ip6tables -A FORWARD -m comment --comment \"Zone global\" -j FWD_global",

            # Rules (none for this test case)

            # Zone closing (global)
            "iptables -A IN_global -j RETURN",
            "ip6tables -A IN_global -j RETURN",
            "iptables -A OUT_global -j RETURN",
            "ip6tables -A OUT_global -j RETURN",
            "iptables -A FWD_global -j RETURN",
            "ip6tables -A FWD_global -j RETURN",

            # Default policies
            "iptables -A INPUT -j REJECT",
            "ip6tables -A INPUT -j REJECT",
            "iptables -A OUTPUT -j ACCEPT",
            "ip6tables -A OUTPUT -j ACCEPT",
            "iptables -A FORWARD -j DROP",
            "ip6tables -A FORWARD -j DROP",
        ]

        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

    def test_case_3_diverse_rules(self):
        config_content = """
[fwsimple]
rulesets = %%RULESETS_DIR%%
engine = iptables

[policy]
in = discard
out = accept
forward = discard

[zones]
ext = eth0
int = eth1
dmz = eth2:10.0.1.0/24
"""
        rules_files: Dict[str, str] = {
            "simple_test_rule.rule": """[allow_ssh_on_ext]
zone = ext
direction = in
protocol = tcp
port = 22
action = accept
log = true"""
        }

        # Expected commands for the simplified test case (110 commands)
        expected_commands = [
            # 1. Init Commands (31 commands)
            "iptables -F", "ip6tables -F",
            "iptables -X", "ip6tables -X",
            "iptables -Z", "ip6tables -Z",
            "iptables -A INPUT -i lo -j ACCEPT", "ip6tables -A INPUT -i lo -j ACCEPT",
            "iptables -A OUTPUT -o lo -j ACCEPT", "ip6tables -A OUTPUT -o lo -j ACCEPT",
            "iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", "ip6tables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", "ip6tables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", "ip6tables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "iptables -A INPUT -m conntrack --ctstate INVALID -j DROP", "ip6tables -A INPUT -m conntrack --ctstate INVALID -j DROP",
            "iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT -m comment --comment \"[ICMP] Echo Request\"",
            "iptables -A INPUT -p icmp -m icmp --icmp-type 3/4 -j ACCEPT -m comment --comment \"[ICMP] Fragmentation needed\"",
            "iptables -A INPUT -p icmp -m icmp --icmp-type 3/3 -j ACCEPT -m comment --comment \"[ICMP] Port unreachable\"",
            "iptables -A INPUT -p icmp -m icmp --icmp-type 3/1 -j ACCEPT -m comment --comment \"[ICMP] Host unreachable\"",
            "iptables -A INPUT -p icmp -m icmp --icmp-type 4 -j ACCEPT -m comment --comment \"[ICMP] Source Quench (RFC 792)\"",
            "ip6tables -A INPUT -p 59 -j ACCEPT -m comment --comment \"[IPv6] No next header RFC2460\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 2 -j ACCEPT -m comment --comment \"[ICMPv6] Packet too big\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 3 -j ACCEPT -m comment --comment \"[ICMPv6] Time exceeded\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 133 -j ACCEPT -m comment --comment \"[ICMPv6] Router sollicitation\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 134 -j ACCEPT -m comment --comment \"[ICMPv6] Router advertisement\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 135 -j ACCEPT -m comment --comment \"[ICMPv6] Neighbor sollicitation\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 136 -j ACCEPT -m comment --comment \"[ICMPv6] Neighbor advertisement\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 128 -j ACCEPT -m comment --comment \"[ICMPv6] Echo Request\"",

            # 2. Zone Creation (24 commands for 4 zones: global, dmz, ext, int)
            # Order for -N commands: global, dmz, ext, int
            "iptables -N IN_global", "ip6tables -N IN_global",
            "iptables -N OUT_global", "ip6tables -N OUT_global",
            "iptables -N FWD_global", "ip6tables -N FWD_global",
            "iptables -N IN_dmz", "ip6tables -N IN_dmz",
            "iptables -N OUT_dmz", "ip6tables -N OUT_dmz",
            "iptables -N FWD_dmz", "ip6tables -N FWD_dmz",
            "iptables -N IN_ext", "ip6tables -N IN_ext",
            "iptables -N OUT_ext", "ip6tables -N OUT_ext",
            "iptables -N FWD_ext", "ip6tables -N FWD_ext",
            "iptables -N IN_int", "ip6tables -N IN_int",
            "iptables -N OUT_int", "ip6tables -N OUT_int",
            "iptables -N FWD_int", "ip6tables -N FWD_int",

            # 3. Zone Expression Creation (21 commands - Order: global, dmz, ext, int)
            "iptables -A INPUT -m comment --comment \"Zone global\" -j IN_global", "ip6tables -A INPUT -m comment --comment \"Zone global\" -j IN_global",
            "iptables -A OUTPUT -m comment --comment \"Zone global\" -j OUT_global", "ip6tables -A OUTPUT -m comment --comment \"Zone global\" -j OUT_global",
            "iptables -A FORWARD -m comment --comment \"Zone global\" -j FWD_global", "ip6tables -A FORWARD -m comment --comment \"Zone global\" -j FWD_global",
            "iptables -A INPUT -i eth2 -s 10.0.1.0/24 -m comment --comment \"Zone dmz\" -j IN_dmz",
            "iptables -A OUTPUT -o eth2 -d 10.0.1.0/24 -m comment --comment \"Zone dmz\" -j OUT_dmz",
            "iptables -A FORWARD -i eth2 -s 10.0.1.0/24 -m comment --comment \"Zone dmz\" -j FWD_dmz",
            "iptables -A INPUT -i eth0 -m comment --comment \"Zone ext\" -j IN_ext", "ip6tables -A INPUT -i eth0 -m comment --comment \"Zone ext\" -j IN_ext",
            "iptables -A OUTPUT -o eth0 -m comment --comment \"Zone ext\" -j OUT_ext", "ip6tables -A OUTPUT -o eth0 -m comment --comment \"Zone ext\" -j OUT_ext",
            "iptables -A FORWARD -i eth0 -m comment --comment \"Zone ext\" -j FWD_ext", "ip6tables -A FORWARD -i eth0 -m comment --comment \"Zone ext\" -j FWD_ext",
            "iptables -A INPUT -i eth1 -m comment --comment \"Zone int\" -j IN_int", "ip6tables -A INPUT -i eth1 -m comment --comment \"Zone int\" -j IN_int",
            "iptables -A OUTPUT -o eth1 -m comment --comment \"Zone int\" -j OUT_int", "ip6tables -A OUTPUT -o eth1 -m comment --comment \"Zone int\" -j OUT_int",
            "iptables -A FORWARD -i eth1 -m comment --comment \"Zone int\" -j FWD_int", "ip6tables -A FORWARD -i eth1 -m comment --comment \"Zone int\" -j FWD_int",

            # 4. Rule Creation (4 commands for simple_test_rule.rule::allow_ssh_on_ext)
            "iptables -A IN_ext -m conntrack --ctstate NEW -m comment --comment simple_test_rule.rule::allow_ssh_on_ext -p tcp --dport 22 -j LOG --log-prefix \"simple_test_rule.rule::allo \"",
            "iptables -A IN_ext -m conntrack --ctstate NEW -m comment --comment simple_test_rule.rule::allow_ssh_on_ext -p tcp --dport 22 -j ACCEPT",
            "ip6tables -A IN_ext -m conntrack --ctstate NEW -m comment --comment simple_test_rule.rule::allow_ssh_on_ext -p tcp --dport 22 -j LOG --log-prefix \"simple_test_rule.rule::allo \"",
            "ip6tables -A IN_ext -m conntrack --ctstate NEW -m comment --comment simple_test_rule.rule::allow_ssh_on_ext -p tcp --dport 22 -j ACCEPT",

            # 5. Zone Closing (24 commands for 4 zones)
            # Order for -A ... -j RETURN commands: global, dmz, ext, int
            "iptables -A IN_global -j RETURN", "ip6tables -A IN_global -j RETURN",
            "iptables -A OUT_global -j RETURN", "ip6tables -A OUT_global -j RETURN",
            "iptables -A FWD_global -j RETURN", "ip6tables -A FWD_global -j RETURN",
            "iptables -A IN_dmz -j RETURN", "ip6tables -A IN_dmz -j RETURN",
            "iptables -A OUT_dmz -j RETURN", "ip6tables -A OUT_dmz -j RETURN",
            "iptables -A FWD_dmz -j RETURN", "ip6tables -A FWD_dmz -j RETURN",
            "iptables -A IN_ext -j RETURN", "ip6tables -A IN_ext -j RETURN",
            "iptables -A OUT_ext -j RETURN", "ip6tables -A OUT_ext -j RETURN",
            "iptables -A FWD_ext -j RETURN", "ip6tables -A FWD_ext -j RETURN",
            "iptables -A IN_int -j RETURN", "ip6tables -A IN_int -j RETURN",
            "iptables -A OUT_int -j RETURN", "ip6tables -A OUT_int -j RETURN",
            "iptables -A FWD_int -j RETURN", "ip6tables -A FWD_int -j RETURN",

            # 6. Default Policies (6 commands - in=discard, out=accept, forward=discard)
            "iptables -A INPUT -j DROP", "ip6tables -A INPUT -j DROP",
            "iptables -A OUTPUT -j ACCEPT", "ip6tables -A OUTPUT -j ACCEPT",
            "iptables -A FORWARD -j DROP", "ip6tables -A FORWARD -j DROP",
        ]

        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

    def test_case_2_zone_expressions(self):
        config_content = """
[fwsimple]
rulesets = %%RULESETS_DIR%%
engine = iptables

[policy]
in = discard
out = accept
forward = discard

[zones]
public = eth0
private_lan = eth1:192.168.1.0/24
guest_wifi = eth1:192.168.2.0/24
vpn_users = tun0
"""
        rules_files: Dict[str, str] = {}

        # Expected commands will need to be replaced with IPTables equivalents
        expected_commands = [
            # 1. Init Commands (31 commands total)
            # constants.BASIC_IPTABLES_INIT (9 definitions * 2 for iptables/ip6tables = 18 commands)
            "iptables -F", "ip6tables -F",
            "iptables -X", "ip6tables -X",
            "iptables -Z", "ip6tables -Z",
            "iptables -A INPUT -i lo -j ACCEPT", "ip6tables -A INPUT -i lo -j ACCEPT",
            "iptables -A OUTPUT -o lo -j ACCEPT", "ip6tables -A OUTPUT -o lo -j ACCEPT",
            "iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", "ip6tables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", "ip6tables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", "ip6tables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "iptables -A INPUT -m conntrack --ctstate INVALID -j DROP", "ip6tables -A INPUT -m conntrack --ctstate INVALID -j DROP",
            # constants.BASIC_IP4TABLES_INIT (5 commands for iptables)
            "iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT -m comment --comment \"[ICMP] Echo Request\"",
            "iptables -A INPUT -p icmp -m icmp --icmp-type 3/4 -j ACCEPT -m comment --comment \"[ICMP] Fragmentation needed\"",
            "iptables -A INPUT -p icmp -m icmp --icmp-type 3/3 -j ACCEPT -m comment --comment \"[ICMP] Port unreachable\"",
            "iptables -A INPUT -p icmp -m icmp --icmp-type 3/1 -j ACCEPT -m comment --comment \"[ICMP] Host unreachable\"",
            "iptables -A INPUT -p icmp -m icmp --icmp-type 4 -j ACCEPT -m comment --comment \"[ICMP] Source Quench (RFC 792)\"",
            # constants.BASIC_IP6TABLES_INIT (8 commands for ip6tables)
            "ip6tables -A INPUT -p 59 -j ACCEPT -m comment --comment \"[IPv6] No next header RFC2460\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 2 -j ACCEPT -m comment --comment \"[ICMPv6] Packet too big\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 3 -j ACCEPT -m comment --comment \"[ICMPv6] Time exceeded\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 133 -j ACCEPT -m comment --comment \"[ICMPv6] Router sollicitation\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 134 -j ACCEPT -m comment --comment \"[ICMPv6] Router advertisement\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 135 -j ACCEPT -m comment --comment \"[ICMPv6] Neighbor sollicitation\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 136 -j ACCEPT -m comment --comment \"[ICMPv6] Neighbor advertisement\"",
            "ip6tables -A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 128 -j ACCEPT -m comment --comment \"[ICMPv6] Echo Request\"",

            # 2. Zone Creation (30 commands for 5 zones: global, guest_wifi, private_lan, public, vpn_users)
            # Zone order for -N commands: global, guest_wifi, private_lan, public, vpn_users
            "iptables -N IN_global", "ip6tables -N IN_global",
            "iptables -N OUT_global", "ip6tables -N OUT_global",
            "iptables -N FWD_global", "ip6tables -N FWD_global",
            "iptables -N IN_guest_wifi", "ip6tables -N IN_guest_wifi",
            "iptables -N OUT_guest_wifi", "ip6tables -N OUT_guest_wifi",
            "iptables -N FWD_guest_wifi", "ip6tables -N FWD_guest_wifi",
            "iptables -N IN_private_lan", "ip6tables -N IN_private_lan",
            "iptables -N OUT_private_lan", "ip6tables -N OUT_private_lan",
            "iptables -N FWD_private_lan", "ip6tables -N FWD_private_lan",
            "iptables -N IN_public", "ip6tables -N IN_public",
            "iptables -N OUT_public", "ip6tables -N OUT_public",
            "iptables -N FWD_public", "ip6tables -N FWD_public",
            "iptables -N IN_vpn_users", "ip6tables -N IN_vpn_users",
            "iptables -N OUT_vpn_users", "ip6tables -N OUT_vpn_users",
            "iptables -N FWD_vpn_users", "ip6tables -N FWD_vpn_users",

            # 3. Zone Expression Creation (24 commands - Order: global, guest_wifi, private_lan, public, vpn_users)
            "iptables -A INPUT -m comment --comment \"Zone global\" -j IN_global", "ip6tables -A INPUT -m comment --comment \"Zone global\" -j IN_global",
            "iptables -A OUTPUT -m comment --comment \"Zone global\" -j OUT_global", "ip6tables -A OUTPUT -m comment --comment \"Zone global\" -j OUT_global",
            "iptables -A FORWARD -m comment --comment \"Zone global\" -j FWD_global", "ip6tables -A FORWARD -m comment --comment \"Zone global\" -j FWD_global",
            "iptables -A INPUT -i eth1 -s 192.168.2.0/24 -m comment --comment \"Zone guest_wifi\" -j IN_guest_wifi",
            "iptables -A OUTPUT -o eth1 -d 192.168.2.0/24 -m comment --comment \"Zone guest_wifi\" -j OUT_guest_wifi",
            "iptables -A FORWARD -i eth1 -s 192.168.2.0/24 -m comment --comment \"Zone guest_wifi\" -j FWD_guest_wifi",
            "iptables -A INPUT -i eth1 -s 192.168.1.0/24 -m comment --comment \"Zone private_lan\" -j IN_private_lan",
            "iptables -A OUTPUT -o eth1 -d 192.168.1.0/24 -m comment --comment \"Zone private_lan\" -j OUT_private_lan",
            "iptables -A FORWARD -i eth1 -s 192.168.1.0/24 -m comment --comment \"Zone private_lan\" -j FWD_private_lan",
            "iptables -A INPUT -i eth0 -m comment --comment \"Zone public\" -j IN_public", "ip6tables -A INPUT -i eth0 -m comment --comment \"Zone public\" -j IN_public",
            "iptables -A OUTPUT -o eth0 -m comment --comment \"Zone public\" -j OUT_public", "ip6tables -A OUTPUT -o eth0 -m comment --comment \"Zone public\" -j OUT_public",
            "iptables -A FORWARD -i eth0 -m comment --comment \"Zone public\" -j FWD_public", "ip6tables -A FORWARD -i eth0 -m comment --comment \"Zone public\" -j FWD_public",
            "iptables -A INPUT -i tun0 -m comment --comment \"Zone vpn_users\" -j IN_vpn_users", "ip6tables -A INPUT -i tun0 -m comment --comment \"Zone vpn_users\" -j IN_vpn_users",
            "iptables -A OUTPUT -o tun0 -m comment --comment \"Zone vpn_users\" -j OUT_vpn_users", "ip6tables -A OUTPUT -o tun0 -m comment --comment \"Zone vpn_users\" -j OUT_vpn_users",
            "iptables -A FORWARD -i tun0 -m comment --comment \"Zone vpn_users\" -j FWD_vpn_users", "ip6tables -A FORWARD -i tun0 -m comment --comment \"Zone vpn_users\" -j FWD_vpn_users",

            # 4. Zone Closing (30 commands for 5 zones)
            # Zone order for -A ... -j RETURN commands: global, guest_wifi, private_lan, public, vpn_users
            "iptables -A IN_global -j RETURN", "ip6tables -A IN_global -j RETURN",
            "iptables -A OUT_global -j RETURN", "ip6tables -A OUT_global -j RETURN",
            "iptables -A FWD_global -j RETURN", "ip6tables -A FWD_global -j RETURN",
            "iptables -A IN_guest_wifi -j RETURN", "ip6tables -A IN_guest_wifi -j RETURN",
            "iptables -A OUT_guest_wifi -j RETURN", "ip6tables -A OUT_guest_wifi -j RETURN",
            "iptables -A FWD_guest_wifi -j RETURN", "ip6tables -A FWD_guest_wifi -j RETURN",
            "iptables -A IN_private_lan -j RETURN", "ip6tables -A IN_private_lan -j RETURN",
            "iptables -A OUT_private_lan -j RETURN", "ip6tables -A OUT_private_lan -j RETURN",
            "iptables -A FWD_private_lan -j RETURN", "ip6tables -A FWD_private_lan -j RETURN",
            "iptables -A IN_public -j RETURN", "ip6tables -A IN_public -j RETURN",
            "iptables -A OUT_public -j RETURN", "ip6tables -A OUT_public -j RETURN",
            "iptables -A FWD_public -j RETURN", "ip6tables -A FWD_public -j RETURN",
            "iptables -A IN_vpn_users -j RETURN", "ip6tables -A IN_vpn_users -j RETURN",
            "iptables -A OUT_vpn_users -j RETURN", "ip6tables -A OUT_vpn_users -j RETURN",
            "iptables -A FWD_vpn_users -j RETURN", "ip6tables -A FWD_vpn_users -j RETURN",

            # 5. Default Policies (6 commands - in=discard, out=accept, forward=discard)
            "iptables -A INPUT -j DROP", "ip6tables -A INPUT -j DROP",
            "iptables -A OUTPUT -j ACCEPT", "ip6tables -A OUTPUT -j ACCEPT",
            "iptables -A FORWARD -j DROP", "ip6tables -A FORWARD -j DROP",
        ]

        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

if __name__ == '__main__':
    unittest.main()
