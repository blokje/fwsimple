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
from tests.test_helper import EngineTestCaseBase

# Ensure NFTABLES_ACTIONS and NFTABLES_BASE_CHAINS are accessible if needed directly
# For now, we rely on the Firewall class to use its engine's definitions.

class NftablesTestCase(EngineTestCaseBase):
    def _normalize_command(self, cmd_str: str) -> str:
        # nftables specific normalization
        return cmd_str.replace("nft ", "", 1).strip()

class TestNftablesEngine(NftablesTestCase):

    def test_case_1_basic_init_and_default_policies(self):
        config_content = """
[fwsimple]
rulesets = %%RULESETS_DIR%%
engine = nftables

[policy]
in = reject
out = accept
forward = discard

[zones]
; No specific zones, only global should be created
"""
        rules_files: Dict[str, str] = {} # No rule files

        # Expected commands (nft prefix will be stripped by assert_commands_equal helper)
        # Order matters here.
        expected_commands = [
            "flush ruleset",
            "add table inet fwsimple",
            "add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy accept ; }\"",
            "add chain inet fwsimple forward \"{ type filter hook forward priority 0 ; policy accept ; }\"",
            "add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
            "nft add rule inet fwsimple input iif lo accept comment \"\\\"Allow all loopback input\\\"\"",
            "nft add rule inet fwsimple output oif lo accept comment \"\\\"Allow all loopback output\\\"\"",
            "add rule inet fwsimple input ct state related,established accept",
            "add rule inet fwsimple output ct state related,established accept",
            "add rule inet fwsimple forward ct state related,established accept",
            "add rule inet fwsimple input ct state invalid drop",
            "add rule inet fwsimple forward ct state invalid drop",
            "nft add rule inet fwsimple input ip version 4 icmp type echo-request accept comment \"\\\"[ICMP] Echo Request\\\"\"",
            "nft add rule inet fwsimple input ip version 4 icmp code frag-needed accept comment \"\\\"[ICMP] Fragmentation needed\\\"\"",
            "nft add rule inet fwsimple input ip version 4 icmp code port-unreachable accept comment \"\\\"[ICMP] Port unreachable\\\"\"",
            "nft add rule inet fwsimple input ip version 4 icmp code host-unreachable accept comment \"\\\"[ICMP] Host unreachable\\\"\"",
            "nft add rule inet fwsimple input ip version 4 icmp type source-quench accept comment \"\\\"[ICMP] Source Quench (RFC 792)\\\"\"",
            "nft add rule inet fwsimple input ip version 6 meta l4proto ipv6-nonxt accept comment \"\\\"[IPv6] No next header RFC2460\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type packet-too-big accept comment \"\\\"[ICMPv6] Packet too big\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type time-exceeded accept comment \"\\\"[ICMPv6] Time exceeded\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type 133 accept comment \"\\\"[ICMPv6] Router sollicitation\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type 134 accept comment \"\\\"[ICMPv6] Router advertisement\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type 135 accept comment \"\\\"[ICMPv6] Neighbor sollicitation\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type 136 accept comment \"\\\"[ICMPv6] Neighbor advertisement\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type echo-request accept comment \"\\\"[ICMPv6] Echo Request\\\"\"",

            # Global zone creation (constants.GLOBAL_ZONE_NAME is 'global')
            "add chain inet fwsimple ZONE_IN_global",
            "add chain inet fwsimple ZONE_OUT_global",
            "add chain inet fwsimple ZONE_FWD_global",

            # Global zone expressions (linking from base chains)
            # For global zone, no interface or IP, so it's just a jump with comment
            "add rule inet fwsimple input jump ZONE_IN_global comment \"\\\"Zone global\\\"\"",
            "add rule inet fwsimple output jump ZONE_OUT_global comment \"\\\"Zone global\\\"\"",
            "add rule inet fwsimple forward jump ZONE_FWD_global comment \"\\\"Zone global\\\"\"",

            # Global zone closing
            "add rule inet fwsimple ZONE_IN_global return",
            "add rule inet fwsimple ZONE_OUT_global return",
            "add rule inet fwsimple ZONE_FWD_global return",

            # Default policy application
            "add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy drop ; }\"",
            "add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
            "add chain inet fwsimple forward \"{ type filter hook forward priority 0 ; policy drop ; }\"",
        ]

        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

    def test_case_3_diverse_rules(self):
        config_content = """
[fwsimple]
rulesets = %%RULESETS_DIR%%
engine = nftables

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
            "test_rules.rule": """
[tcp_ssh_from_host_to_int]
zone = int
direction = in
protocol = tcp
port = 22
source = 192.168.1.100
action = accept

[tcp_web_ports_logged_to_ext]
zone = ext
direction = in
protocol = tcp
port = 80,443
action = accept
log = true

[tcp_custom_app_range_to_int]
zone = int
direction = in
protocol = tcp
port = 1000-1010
action = accept
multiport = true

[udp_dns_to_server_from_ext]
zone = ext
direction = out
protocol = udp
port = 53
destination = 8.8.8.8
action = accept

[icmp_ping_from_int]
zone = int
direction = in
protocol = icmp
action = accept

[reject_all_tcp_to_dmz]
zone = dmz
direction = in
protocol = tcp
action = reject

[discard_udp_5000_to_ext]
zone = ext
direction = in
protocol = udp
port = 5000
action = discard

[tcp6_ssh_from_host_to_int]
zone = int
direction = in
protocol = tcp
port = 22
source = 2001:db8:cafe:1::100
action = accept

[udp6_dns_to_server_from_ext]
zone = ext
direction = out
protocol = udp
port = 53
destination = 2001:db8:feed::1
action = accept
log = true

[icmp6_ping_host_from_int]
zone = int
direction = out
protocol = icmpv6
destination = 2001:db8:dead::beef
action = accept
"""
        }

        expected_commands = [
            # 1. Init
            "nft flush ruleset",
            "nft add table inet fwsimple",
            "nft add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy accept ; }\"",
            "nft add chain inet fwsimple forward \"{ type filter hook forward priority 0 ; policy accept ; }\"",
            "nft add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
            "nft add rule inet fwsimple input iif lo accept comment \"\\\"Allow all loopback input\\\"\"",
            "nft add rule inet fwsimple output oif lo accept comment \"\\\"Allow all loopback output\\\"\"",
            "nft add rule inet fwsimple input ct state related,established accept",
            "nft add rule inet fwsimple output ct state related,established accept",
            "nft add rule inet fwsimple forward ct state related,established accept",
            "nft add rule inet fwsimple input ct state invalid drop",
            "nft add rule inet fwsimple forward ct state invalid drop",
            "nft add rule inet fwsimple input ip version 4 icmp type echo-request accept comment \"\\\"[ICMP] Echo Request\\\"\"",
            "nft add rule inet fwsimple input ip version 4 icmp code frag-needed accept comment \"\\\"[ICMP] Fragmentation needed\\\"\"",
            "nft add rule inet fwsimple input ip version 4 icmp code port-unreachable accept comment \"\\\"[ICMP] Port unreachable\\\"\"",
            "nft add rule inet fwsimple input ip version 4 icmp code host-unreachable accept comment \"\\\"[ICMP] Host unreachable\\\"\"",
            "nft add rule inet fwsimple input ip version 4 icmp type source-quench accept comment \"\\\"[ICMP] Source Quench (RFC 792)\\\"\"",
            "nft add rule inet fwsimple input ip version 6 meta l4proto ipv6-nonxt accept comment \"\\\"[IPv6] No next header RFC2460\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type packet-too-big accept comment \"\\\"[ICMPv6] Packet too big\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type time-exceeded accept comment \"\\\"[ICMPv6] Time exceeded\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type 133 accept comment \"\\\"[ICMPv6] Router sollicitation\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type 134 accept comment \"\\\"[ICMPv6] Router advertisement\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type 135 accept comment \"\\\"[ICMPv6] Neighbor sollicitation\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type 136 accept comment \"\\\"[ICMPv6] Neighbor advertisement\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type echo-request accept comment \"\\\"[ICMPv6] Echo Request\\\"\"",

            # 2. Zone Creation
            "nft add chain inet fwsimple ZONE_IN_global", "nft add chain inet fwsimple ZONE_OUT_global", "nft add chain inet fwsimple ZONE_FWD_global",
            "nft add chain inet fwsimple ZONE_IN_ext", "nft add chain inet fwsimple ZONE_OUT_ext", "nft add chain inet fwsimple ZONE_FWD_ext",
            "nft add chain inet fwsimple ZONE_IN_int", "nft add chain inet fwsimple ZONE_OUT_int", "nft add chain inet fwsimple ZONE_FWD_int",
            "nft add chain inet fwsimple ZONE_IN_dmz", "nft add chain inet fwsimple ZONE_OUT_dmz", "nft add chain inet fwsimple ZONE_FWD_dmz",

            # 3. Zone Expression Creation (Order: global, dmz (specific), ext (generic), int (generic))
            "nft add rule inet fwsimple input jump ZONE_IN_global comment \"\\\"Zone global\\\"\"",
            "nft add rule inet fwsimple output jump ZONE_OUT_global comment \"\\\"Zone global\\\"\"",
            "nft add rule inet fwsimple forward jump ZONE_FWD_global comment \"\\\"Zone global\\\"\"",
            "nft add rule inet fwsimple input iif eth2 ip saddr 10.0.1.0/24 jump ZONE_IN_dmz comment \"\\\"Zone dmz\\\"\"",
            "nft add rule inet fwsimple output oif eth2 ip daddr 10.0.1.0/24 jump ZONE_OUT_dmz comment \"\\\"Zone dmz\\\"\"",
            "nft add rule inet fwsimple forward iif eth2 ip saddr 10.0.1.0/24 jump ZONE_FWD_dmz comment \"\\\"Zone dmz\\\"\"",
            "nft add rule inet fwsimple input iif eth0 jump ZONE_IN_ext comment \"\\\"Zone ext\\\"\"",
            "nft add rule inet fwsimple output oif eth0 jump ZONE_OUT_ext comment \"\\\"Zone ext\\\"\"",
            "nft add rule inet fwsimple forward iif eth0 jump ZONE_FWD_ext comment \"\\\"Zone ext\\\"\"",
            "nft add rule inet fwsimple input iif eth1 jump ZONE_IN_int comment \"\\\"Zone int\\\"\"",
            "nft add rule inet fwsimple output oif eth1 jump ZONE_OUT_int comment \"\\\"Zone int\\\"\"",
            "nft add rule inet fwsimple forward iif eth1 jump ZONE_FWD_int comment \"\\\"Zone int\\\"\"",

            # 4. Rule Creation (Order by action: discard, reject, accept; then file order)
            "nft add rule inet fwsimple ZONE_IN_ext ct state new udp dport 5000 drop comment \\\"test_rules.rule::discard_udp_5000_to_ext\\\"",
            "nft add rule inet fwsimple ZONE_IN_dmz ct state new tcp reject comment \\\"test_rules.rule::reject_all_tcp_to_dmz\\\"",
            "nft add rule inet fwsimple ZONE_IN_int ct state new tcp dport 22 ip saddr 192.168.1.100/32 accept comment \\\"test_rules.rule::tcp_ssh_from_host_to_int\\\"",
            "nft add rule inet fwsimple ZONE_IN_ext ct state new tcp dport \"{ 80, 443 }\" log prefix \"test_rules.rule::tcp_web: \" accept comment \\\"test_rules.rule::tcp_web_ports_logged_to_ext\\\"",
            "nft add rule inet fwsimple ZONE_IN_int ct state new tcp dport \"{ 1000-1010 }\" accept comment \\\"test_rules.rule::tcp_custom_app_range_to_int\\\"",
            "nft add rule inet fwsimple ZONE_OUT_ext ct state new udp dport 53 ip daddr 8.8.8.8/32 accept comment \\\"test_rules.rule::udp_dns_to_server_from_ext\\\"",
            "nft add rule inet fwsimple ZONE_IN_int ct state new icmp accept comment \\\"test_rules.rule::icmp_ping_from_int\\\"",
            "nft add rule inet fwsimple ZONE_IN_int ct state new tcp dport 22 ip6 saddr 2001:db8:cafe:1::100/128 accept comment \\\"test_rules.rule::tcp6_ssh_from_host_to_int\\\"",
            "nft add rule inet fwsimple ZONE_OUT_ext ct state new udp dport 53 ip6 daddr 2001:db8:feed::1/128 log prefix \"test_rules.rule::udp6_dn: \" accept comment \\\"test_rules.rule::udp6_dns_to_server_from_ext\\\"",
            "nft add rule inet fwsimple ZONE_OUT_int ct state new icmpv6 ip6 daddr 2001:db8:dead::beef/128 accept comment \\\"test_rules.rule::icmp6_ping_host_from_int\\\"",

            # 5. Zone Closing
            "nft add rule inet fwsimple ZONE_IN_global return", "nft add rule inet fwsimple ZONE_OUT_global return", "nft add rule inet fwsimple ZONE_FWD_global return",
            "nft add rule inet fwsimple ZONE_IN_ext return", "nft add rule inet fwsimple ZONE_OUT_ext return", "nft add rule inet fwsimple ZONE_FWD_ext return",
            "nft add rule inet fwsimple ZONE_IN_int return", "nft add rule inet fwsimple ZONE_OUT_int return", "nft add rule inet fwsimple ZONE_FWD_int return",
            "nft add rule inet fwsimple ZONE_IN_dmz return", "nft add rule inet fwsimple ZONE_OUT_dmz return", "nft add rule inet fwsimple ZONE_FWD_dmz return",

            # 6. Default Policy Application
            "nft add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy drop ; }\"",
            "nft add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
            "nft add chain inet fwsimple forward \"{ type filter hook forward priority 0 ; policy drop ; }\"",
        ]

        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

    def test_case_2_zone_expressions(self):
        config_content = """
[fwsimple]
rulesets = %%RULESETS_DIR%%
engine = nftables

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

        expected_commands = [
            # 1. Init
            "nft flush ruleset",
            "nft add table inet fwsimple",
            "nft add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy accept ; }\"",
            "nft add chain inet fwsimple forward \"{ type filter hook forward priority 0 ; policy accept ; }\"",
            "nft add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
            "nft add rule inet fwsimple input iif lo accept comment \"\\\"Allow all loopback input\\\"\"",
            "nft add rule inet fwsimple output oif lo accept comment \"\\\"Allow all loopback output\\\"\"",
            "nft add rule inet fwsimple input ct state related,established accept",
            "nft add rule inet fwsimple output ct state related,established accept",
            "nft add rule inet fwsimple forward ct state related,established accept",
            "nft add rule inet fwsimple input ct state invalid drop",
            "nft add rule inet fwsimple forward ct state invalid drop",
            "nft add rule inet fwsimple input ip version 4 icmp type echo-request accept comment \"\\\"[ICMP] Echo Request\\\"\"",
            "nft add rule inet fwsimple input ip version 4 icmp code frag-needed accept comment \"\\\"[ICMP] Fragmentation needed\\\"\"",
            "nft add rule inet fwsimple input ip version 4 icmp code port-unreachable accept comment \"\\\"[ICMP] Port unreachable\\\"\"",
            "nft add rule inet fwsimple input ip version 4 icmp code host-unreachable accept comment \"\\\"[ICMP] Host unreachable\\\"\"",
            "nft add rule inet fwsimple input ip version 4 icmp type source-quench accept comment \"\\\"[ICMP] Source Quench (RFC 792)\\\"\"",
            "nft add rule inet fwsimple input ip version 6 meta l4proto ipv6-nonxt accept comment \"\\\"[IPv6] No next header RFC2460\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type packet-too-big accept comment \"\\\"[ICMPv6] Packet too big\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type time-exceeded accept comment \"\\\"[ICMPv6] Time exceeded\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type 133 accept comment \"\\\"[ICMPv6] Router sollicitation\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type 134 accept comment \"\\\"[ICMPv6] Router advertisement\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type 135 accept comment \"\\\"[ICMPv6] Neighbor sollicitation\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type 136 accept comment \"\\\"[ICMPv6] Neighbor advertisement\\\"\"",
            "nft add rule inet fwsimple input ip version 6 icmpv6 type echo-request accept comment \"\\\"[ICMPv6] Echo Request\\\"\"",

            # 2. Zone Creation
            "nft add chain inet fwsimple ZONE_IN_global",
            "nft add chain inet fwsimple ZONE_OUT_global",
            "nft add chain inet fwsimple ZONE_FWD_global",
            "nft add chain inet fwsimple ZONE_IN_public",
            "nft add chain inet fwsimple ZONE_OUT_public",
            "nft add chain inet fwsimple ZONE_FWD_public",
            "nft add chain inet fwsimple ZONE_IN_private_lan",
            "nft add chain inet fwsimple ZONE_OUT_private_lan",
            "nft add chain inet fwsimple ZONE_FWD_private_lan",
            "nft add chain inet fwsimple ZONE_IN_guest_wifi",
            "nft add chain inet fwsimple ZONE_OUT_guest_wifi",
            "nft add chain inet fwsimple ZONE_FWD_guest_wifi",
            "nft add chain inet fwsimple ZONE_IN_vpn_users",
            "nft add chain inet fwsimple ZONE_OUT_vpn_users",
            "nft add chain inet fwsimple ZONE_FWD_vpn_users",

            # 3. Zone Expression Creation
            # Order: global, then specific (sorted by num_addresses, then config order), then generic (config order).
            # Global
            "nft add rule inet fwsimple input jump ZONE_IN_global comment \"\\\"Zone global\\\"\"",
            "nft add rule inet fwsimple output jump ZONE_OUT_global comment \"\\\"Zone global\\\"\"",
            "nft add rule inet fwsimple forward jump ZONE_FWD_global comment \"\\\"Zone global\\\"\"",
            # private_lan = eth1:192.168.1.0/24 (Specific)
            "nft add rule inet fwsimple input iif eth1 ip saddr 192.168.1.0/24 jump ZONE_IN_private_lan comment \"\\\"Zone private_lan\\\"\"",
            "nft add rule inet fwsimple output oif eth1 ip daddr 192.168.1.0/24 jump ZONE_OUT_private_lan comment \"\\\"Zone private_lan\\\"\"",
            "nft add rule inet fwsimple forward iif eth1 ip saddr 192.168.1.0/24 jump ZONE_FWD_private_lan comment \"\\\"Zone private_lan\\\"\"",
            # guest_wifi = eth1:192.168.2.0/24 (Specific)
            "nft add rule inet fwsimple input iif eth1 ip saddr 192.168.2.0/24 jump ZONE_IN_guest_wifi comment \"\\\"Zone guest_wifi\\\"\"",
            "nft add rule inet fwsimple output oif eth1 ip daddr 192.168.2.0/24 jump ZONE_OUT_guest_wifi comment \"\\\"Zone guest_wifi\\\"\"",
            "nft add rule inet fwsimple forward iif eth1 ip saddr 192.168.2.0/24 jump ZONE_FWD_guest_wifi comment \"\\\"Zone guest_wifi\\\"\"",
            # public = eth0 (Generic)
            "nft add rule inet fwsimple input iif eth0 jump ZONE_IN_public comment \"\\\"Zone public\\\"\"",
            "nft add rule inet fwsimple output oif eth0 jump ZONE_OUT_public comment \"\\\"Zone public\\\"\"",
            "nft add rule inet fwsimple forward iif eth0 jump ZONE_FWD_public comment \"\\\"Zone public\\\"\"",
            # vpn_users = tun0 (Generic)
            "nft add rule inet fwsimple input iif tun0 jump ZONE_IN_vpn_users comment \"\\\"Zone vpn_users\\\"\"",
            "nft add rule inet fwsimple output oif tun0 jump ZONE_OUT_vpn_users comment \"\\\"Zone vpn_users\\\"\"",
            "nft add rule inet fwsimple forward iif tun0 jump ZONE_FWD_vpn_users comment \"\\\"Zone vpn_users\\\"\"",

            # 4. Rule Creation (none)

            # 5. Zone Closing
            "nft add rule inet fwsimple ZONE_IN_global return",
            "nft add rule inet fwsimple ZONE_OUT_global return",
            "nft add rule inet fwsimple ZONE_FWD_global return",
            "nft add rule inet fwsimple ZONE_IN_public return",
            "nft add rule inet fwsimple ZONE_OUT_public return",
            "nft add rule inet fwsimple ZONE_FWD_public return",
            "nft add rule inet fwsimple ZONE_IN_private_lan return",
            "nft add rule inet fwsimple ZONE_OUT_private_lan return",
            "nft add rule inet fwsimple ZONE_FWD_private_lan return",
            "nft add rule inet fwsimple ZONE_IN_guest_wifi return",
            "nft add rule inet fwsimple ZONE_OUT_guest_wifi return",
            "nft add rule inet fwsimple ZONE_FWD_guest_wifi return",
            "nft add rule inet fwsimple ZONE_IN_vpn_users return",
            "nft add rule inet fwsimple ZONE_OUT_vpn_users return",
            "nft add rule inet fwsimple ZONE_FWD_vpn_users return",

            # 6. Default Policy Application
            "nft add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy drop ; }\"",
            "nft add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
            "nft add chain inet fwsimple forward \"{ type filter hook forward priority 0 ; policy drop ; }\"",
        ]

        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

if __name__ == '__main__':
    unittest.main()
