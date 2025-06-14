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
    default_engine_in_config = 'nftables'

    def _normalize_command(self, cmd_str: str) -> str:
        # nftables specific normalization
        return cmd_str.replace("nft ", "", 1).strip()

class TestNftablesEngine(NftablesTestCase):

    def test_scenario_basic_init(self):
        config_content = self._get_config_basic_init()
        rules_files: Dict[str, str] = {}

        # Taken from old test_case_1_basic_init_and_default_policies
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
            "add chain inet fwsimple ZONE_IN_global",
            "add chain inet fwsimple ZONE_OUT_global",
            "add chain inet fwsimple ZONE_FWD_global",
            "add rule inet fwsimple input jump ZONE_IN_global comment \"\\\"Zone global\\\"\"",
            "add rule inet fwsimple output jump ZONE_OUT_global comment \"\\\"Zone global\\\"\"",
            "add rule inet fwsimple forward jump ZONE_FWD_global comment \"\\\"Zone global\\\"\"",
            "add rule inet fwsimple ZONE_IN_global return",
            "add rule inet fwsimple ZONE_OUT_global return",
            "add rule inet fwsimple ZONE_FWD_global return",
            "add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy drop ; }\"", # reject becomes drop for nftables base policy
            "add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
        ]
        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

    def test_scenario_tcp_allow(self):
        zone_name = "int"
        config_content = self._get_config_one_zone(zone_name=zone_name, zone_def="eth1")
        rules_files = self._get_rules_tcp_allow(zone_name=zone_name, port="22", source="192.168.1.100/32")

        expected_commands = [
            "flush ruleset", "add table inet fwsimple",
            "add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy accept ; }\"",
            "add chain inet fwsimple forward \"{ type filter hook forward priority 0 ; policy accept ; }\"",
            "add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
            "nft add rule inet fwsimple input iif lo accept comment \"\\\"Allow all loopback input\\\"\"",
            "nft add rule inet fwsimple output oif lo accept comment \"\\\"Allow all loopback output\\\"\"",
            "add rule inet fwsimple input ct state related,established accept",
            "add rule inet fwsimple output ct state related,established accept",
            "add rule inet fwsimple forward ct state related,established accept",
            "add rule inet fwsimple input ct state invalid drop", "add rule inet fwsimple forward ct state invalid drop",
            "nft add rule inet fwsimple input ip version 4 icmp type echo-request accept comment \"\\\"[ICMP] Echo Request\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code frag-needed accept comment \"\\\"[ICMP] Fragmentation needed\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code port-unreachable accept comment \"\\\"[ICMP] Port unreachable\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code host-unreachable accept comment \"\\\"[ICMP] Host unreachable\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp type source-quench accept comment \"\\\"[ICMP] Source Quench (RFC 792)\\\"\"",
            "nft add rule inet fwsimple input ip version 6 meta l4proto ipv6-nonxt accept comment \"\\\"[IPv6] No next header RFC2460\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type packet-too-big accept comment \"\\\"[ICMPv6] Packet too big\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type time-exceeded accept comment \"\\\"[ICMPv6] Time exceeded\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 133 accept comment \"\\\"[ICMPv6] Router sollicitation\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 134 accept comment \"\\\"[ICMPv6] Router advertisement\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 135 accept comment \"\\\"[ICMPv6] Neighbor sollicitation\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 136 accept comment \"\\\"[ICMPv6] Neighbor advertisement\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type echo-request accept comment \"\\\"[ICMPv6] Echo Request\\\"\"",
            "add chain inet fwsimple ZONE_IN_global", "add chain inet fwsimple ZONE_OUT_global", "add chain inet fwsimple ZONE_FWD_global",
            "add chain inet fwsimple ZONE_IN_int", "add chain inet fwsimple ZONE_OUT_int", "add chain inet fwsimple ZONE_FWD_int",
            "add rule inet fwsimple input jump ZONE_IN_global comment \"\\\"Zone global\\\"\"", "add rule inet fwsimple output jump ZONE_OUT_global comment \"\\\"Zone global\\\"\"", "add rule inet fwsimple forward jump ZONE_FWD_global comment \"\\\"Zone global\\\"\"",
            "add rule inet fwsimple input iif eth1 jump ZONE_IN_int comment \"\\\"Zone int\\\"\"", "add rule inet fwsimple output oif eth1 jump ZONE_OUT_int comment \"\\\"Zone int\\\"\"", "add rule inet fwsimple forward iif eth1 jump ZONE_FWD_int comment \"\\\"Zone int\\\"\"",
            "nft add rule inet fwsimple ZONE_IN_int ct state new tcp dport 22 ip saddr 192.168.1.100/32 accept comment \\\"tcp_allow.rule::allow_ssh_from_host\\\"",
            "add rule inet fwsimple ZONE_IN_global return", "add rule inet fwsimple ZONE_OUT_global return", "add rule inet fwsimple ZONE_FWD_global return",
            "add rule inet fwsimple ZONE_IN_int return", "add rule inet fwsimple ZONE_OUT_int return", "add rule inet fwsimple ZONE_FWD_int return",
            "add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy drop ; }\"", # reject
            "add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
        ]
        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

    def test_scenario_udp_deny(self):
        zone_name = "ext"
        config_content = self._get_config_one_zone(zone_name=zone_name, zone_def="eth0")
        rules_files = self._get_rules_udp_deny(zone_name=zone_name, port="53", destination="8.8.8.8/32", action="discard") # discard is drop for nftables

        expected_commands = [
            "flush ruleset", "add table inet fwsimple",
            "add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy accept ; }\"", "add chain inet fwsimple forward \"{ type filter hook forward priority 0 ; policy accept ; }\"", "add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
            "nft add rule inet fwsimple input iif lo accept comment \"\\\"Allow all loopback input\\\"\"", "nft add rule inet fwsimple output oif lo accept comment \"\\\"Allow all loopback output\\\"\"",
            "add rule inet fwsimple input ct state related,established accept", "add rule inet fwsimple output ct state related,established accept", "add rule inet fwsimple forward ct state related,established accept",
            "add rule inet fwsimple input ct state invalid drop", "add rule inet fwsimple forward ct state invalid drop",
            "nft add rule inet fwsimple input ip version 4 icmp type echo-request accept comment \"\\\"[ICMP] Echo Request\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code frag-needed accept comment \"\\\"[ICMP] Fragmentation needed\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code port-unreachable accept comment \"\\\"[ICMP] Port unreachable\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code host-unreachable accept comment \"\\\"[ICMP] Host unreachable\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp type source-quench accept comment \"\\\"[ICMP] Source Quench (RFC 792)\\\"\"",
            "nft add rule inet fwsimple input ip version 6 meta l4proto ipv6-nonxt accept comment \"\\\"[IPv6] No next header RFC2460\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type packet-too-big accept comment \"\\\"[ICMPv6] Packet too big\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type time-exceeded accept comment \"\\\"[ICMPv6] Time exceeded\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 133 accept comment \"\\\"[ICMPv6] Router sollicitation\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 134 accept comment \"\\\"[ICMPv6] Router advertisement\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 135 accept comment \"\\\"[ICMPv6] Neighbor sollicitation\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 136 accept comment \"\\\"[ICMPv6] Neighbor advertisement\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type echo-request accept comment \"\\\"[ICMPv6] Echo Request\\\"\"",
            "add chain inet fwsimple ZONE_IN_global", "add chain inet fwsimple ZONE_OUT_global", "add chain inet fwsimple ZONE_FWD_global",
            "add chain inet fwsimple ZONE_IN_ext", "add chain inet fwsimple ZONE_OUT_ext", "add chain inet fwsimple ZONE_FWD_ext",
            "add rule inet fwsimple input jump ZONE_IN_global comment \"\\\"Zone global\\\"\"", "add rule inet fwsimple output jump ZONE_OUT_global comment \"\\\"Zone global\\\"\"", "add rule inet fwsimple forward jump ZONE_FWD_global comment \"\\\"Zone global\\\"\"",
            "add rule inet fwsimple input iif eth0 jump ZONE_IN_ext comment \"\\\"Zone ext\\\"\"", "add rule inet fwsimple output oif eth0 jump ZONE_OUT_ext comment \"\\\"Zone ext\\\"\"", "add rule inet fwsimple forward iif eth0 jump ZONE_FWD_ext comment \"\\\"Zone ext\\\"\"",
            "nft add rule inet fwsimple ZONE_OUT_ext ct state new udp dport 53 ip daddr 8.8.8.8/32 drop comment \\\"udp_deny.rule::deny_dns_to_external\\\"", # discard becomes drop
            "add rule inet fwsimple ZONE_IN_global return", "add rule inet fwsimple ZONE_OUT_global return", "add rule inet fwsimple ZONE_FWD_global return",
            "add rule inet fwsimple ZONE_IN_ext return", "add rule inet fwsimple ZONE_OUT_ext return", "add rule inet fwsimple ZONE_FWD_ext return",
            "add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy drop ; }\"", # reject
            "add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
        ]
        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

    def test_scenario_logged_rule(self):
        zone_name = "ext"
        config_content = self._get_config_one_zone(zone_name=zone_name, zone_def="eth0")
        rules_files = self._get_rules_logged_rule(zone_name=zone_name, port="80", source="any", action="accept")

        expected_commands = [
            "flush ruleset", "add table inet fwsimple",
            "add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy accept ; }\"", "add chain inet fwsimple forward \"{ type filter hook forward priority 0 ; policy accept ; }\"", "add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
            "nft add rule inet fwsimple input iif lo accept comment \"\\\"Allow all loopback input\\\"\"", "nft add rule inet fwsimple output oif lo accept comment \"\\\"Allow all loopback output\\\"\"",
            "add rule inet fwsimple input ct state related,established accept", "add rule inet fwsimple output ct state related,established accept", "add rule inet fwsimple forward ct state related,established accept",
            "add rule inet fwsimple input ct state invalid drop", "add rule inet fwsimple forward ct state invalid drop",
            "nft add rule inet fwsimple input ip version 4 icmp type echo-request accept comment \"\\\"[ICMP] Echo Request\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code frag-needed accept comment \"\\\"[ICMP] Fragmentation needed\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code port-unreachable accept comment \"\\\"[ICMP] Port unreachable\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code host-unreachable accept comment \"\\\"[ICMP] Host unreachable\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp type source-quench accept comment \"\\\"[ICMP] Source Quench (RFC 792)\\\"\"",
            "nft add rule inet fwsimple input ip version 6 meta l4proto ipv6-nonxt accept comment \"\\\"[IPv6] No next header RFC2460\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type packet-too-big accept comment \"\\\"[ICMPv6] Packet too big\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type time-exceeded accept comment \"\\\"[ICMPv6] Time exceeded\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 133 accept comment \"\\\"[ICMPv6] Router sollicitation\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 134 accept comment \"\\\"[ICMPv6] Router advertisement\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 135 accept comment \"\\\"[ICMPv6] Neighbor sollicitation\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 136 accept comment \"\\\"[ICMPv6] Neighbor advertisement\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type echo-request accept comment \"\\\"[ICMPv6] Echo Request\\\"\"",
            "add chain inet fwsimple ZONE_IN_global", "add chain inet fwsimple ZONE_OUT_global", "add chain inet fwsimple ZONE_FWD_global",
            "add chain inet fwsimple ZONE_IN_ext", "add chain inet fwsimple ZONE_OUT_ext", "add chain inet fwsimple ZONE_FWD_ext",
            "add rule inet fwsimple input jump ZONE_IN_global comment \"\\\"Zone global\\\"\"", "add rule inet fwsimple output jump ZONE_OUT_global comment \"\\\"Zone global\\\"\"", "add rule inet fwsimple forward jump ZONE_FWD_global comment \"\\\"Zone global\\\"\"",
            "add rule inet fwsimple input iif eth0 jump ZONE_IN_ext comment \"\\\"Zone ext\\\"\"", "add rule inet fwsimple output oif eth0 jump ZONE_OUT_ext comment \"\\\"Zone ext\\\"\"", "add rule inet fwsimple forward iif eth0 jump ZONE_FWD_ext comment \"\\\"Zone ext\\\"\"",
            "nft add rule inet fwsimple ZONE_IN_ext ct state new tcp dport 80 log prefix \"logged_rule.rule::logged_: \" accept comment \"logged_rule.rule::logged_ssh_rule\"",
            "add rule inet fwsimple ZONE_IN_global return", "add rule inet fwsimple ZONE_OUT_global return", "add rule inet fwsimple ZONE_FWD_global return",
            "add rule inet fwsimple ZONE_IN_ext return", "add rule inet fwsimple ZONE_OUT_ext return", "add rule inet fwsimple ZONE_FWD_ext return",
            "add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy drop ; }\"", # reject
            "add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
        ]
        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

    def test_scenario_multiple_ports(self):
        zone_name = "ext"
        ports = "80,443"
        config_content = self._get_config_one_zone(zone_name=zone_name, zone_def="eth0")
        rules_files = self._get_rules_multiple_ports(zone_name=zone_name, ports=ports, action="accept")

        expected_commands = [
            "flush ruleset", "add table inet fwsimple",
            "add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy accept ; }\"", "add chain inet fwsimple forward \"{ type filter hook forward priority 0 ; policy accept ; }\"", "add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
            "nft add rule inet fwsimple input iif lo accept comment \"\\\"Allow all loopback input\\\"\"", "nft add rule inet fwsimple output oif lo accept comment \"\\\"Allow all loopback output\\\"\"",
            "add rule inet fwsimple input ct state related,established accept", "add rule inet fwsimple output ct state related,established accept", "add rule inet fwsimple forward ct state related,established accept",
            "add rule inet fwsimple input ct state invalid drop", "add rule inet fwsimple forward ct state invalid drop",
            "nft add rule inet fwsimple input ip version 4 icmp type echo-request accept comment \"\\\"[ICMP] Echo Request\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code frag-needed accept comment \"\\\"[ICMP] Fragmentation needed\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code port-unreachable accept comment \"\\\"[ICMP] Port unreachable\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code host-unreachable accept comment \"\\\"[ICMP] Host unreachable\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp type source-quench accept comment \"\\\"[ICMP] Source Quench (RFC 792)\\\"\"",
            "nft add rule inet fwsimple input ip version 6 meta l4proto ipv6-nonxt accept comment \"\\\"[IPv6] No next header RFC2460\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type packet-too-big accept comment \"\\\"[ICMPv6] Packet too big\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type time-exceeded accept comment \"\\\"[ICMPv6] Time exceeded\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 133 accept comment \"\\\"[ICMPv6] Router sollicitation\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 134 accept comment \"\\\"[ICMPv6] Router advertisement\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 135 accept comment \"\\\"[ICMPv6] Neighbor sollicitation\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 136 accept comment \"\\\"[ICMPv6] Neighbor advertisement\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type echo-request accept comment \"\\\"[ICMPv6] Echo Request\\\"\"",
            "add chain inet fwsimple ZONE_IN_global", "add chain inet fwsimple ZONE_OUT_global", "add chain inet fwsimple ZONE_FWD_global",
            "add chain inet fwsimple ZONE_IN_ext", "add chain inet fwsimple ZONE_OUT_ext", "add chain inet fwsimple ZONE_FWD_ext",
            "add rule inet fwsimple input jump ZONE_IN_global comment \"\\\"Zone global\\\"\"", "add rule inet fwsimple output jump ZONE_OUT_global comment \"\\\"Zone global\\\"\"", "add rule inet fwsimple forward jump ZONE_FWD_global comment \"\\\"Zone global\\\"\"",
            "add rule inet fwsimple input iif eth0 jump ZONE_IN_ext comment \"\\\"Zone ext\\\"\"", "add rule inet fwsimple output oif eth0 jump ZONE_OUT_ext comment \"\\\"Zone ext\\\"\"", "add rule inet fwsimple forward iif eth0 jump ZONE_FWD_ext comment \"\\\"Zone ext\\\"\"",
            "nft add rule inet fwsimple ZONE_IN_ext ct state new tcp dport \"{ 80, 443 }\" accept comment \\\"multi_port.rule::allow_web_ports\\\"",
            "add rule inet fwsimple ZONE_IN_global return", "add rule inet fwsimple ZONE_OUT_global return", "add rule inet fwsimple ZONE_FWD_global return",
            "add rule inet fwsimple ZONE_IN_ext return", "add rule inet fwsimple ZONE_OUT_ext return", "add rule inet fwsimple ZONE_FWD_ext return",
            "add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy drop ; }\"", # reject
            "add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
        ]
        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

    def test_scenario_port_range(self):
        zone_name = "int"
        port_range = "1000-1024"
        config_content = self._get_config_one_zone(zone_name=zone_name, zone_def="eth1")
        rules_files = self._get_rules_port_range(zone_name=zone_name, port_range=port_range, action="accept")

        expected_commands = [
            "flush ruleset", "add table inet fwsimple",
            "add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy accept ; }\"", "add chain inet fwsimple forward \"{ type filter hook forward priority 0 ; policy accept ; }\"", "add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
            "nft add rule inet fwsimple input iif lo accept comment \"\\\"Allow all loopback input\\\"\"", "nft add rule inet fwsimple output oif lo accept comment \"\\\"Allow all loopback output\\\"\"",
            "add rule inet fwsimple input ct state related,established accept", "add rule inet fwsimple output ct state related,established accept", "add rule inet fwsimple forward ct state related,established accept",
            "add rule inet fwsimple input ct state invalid drop", "add rule inet fwsimple forward ct state invalid drop",
            "nft add rule inet fwsimple input ip version 4 icmp type echo-request accept comment \"\\\"[ICMP] Echo Request\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code frag-needed accept comment \"\\\"[ICMP] Fragmentation needed\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code port-unreachable accept comment \"\\\"[ICMP] Port unreachable\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code host-unreachable accept comment \"\\\"[ICMP] Host unreachable\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp type source-quench accept comment \"\\\"[ICMP] Source Quench (RFC 792)\\\"\"",
            "nft add rule inet fwsimple input ip version 6 meta l4proto ipv6-nonxt accept comment \"\\\"[IPv6] No next header RFC2460\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type packet-too-big accept comment \"\\\"[ICMPv6] Packet too big\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type time-exceeded accept comment \"\\\"[ICMPv6] Time exceeded\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 133 accept comment \"\\\"[ICMPv6] Router sollicitation\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 134 accept comment \"\\\"[ICMPv6] Router advertisement\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 135 accept comment \"\\\"[ICMPv6] Neighbor sollicitation\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 136 accept comment \"\\\"[ICMPv6] Neighbor advertisement\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type echo-request accept comment \"\\\"[ICMPv6] Echo Request\\\"\"",
            "add chain inet fwsimple ZONE_IN_global", "add chain inet fwsimple ZONE_OUT_global", "add chain inet fwsimple ZONE_FWD_global",
            "add chain inet fwsimple ZONE_IN_int", "add chain inet fwsimple ZONE_OUT_int", "add chain inet fwsimple ZONE_FWD_int",
            "add rule inet fwsimple input jump ZONE_IN_global comment \"\\\"Zone global\\\"\"", "add rule inet fwsimple output jump ZONE_OUT_global comment \"\\\"Zone global\\\"\"", "add rule inet fwsimple forward jump ZONE_FWD_global comment \"\\\"Zone global\\\"\"",
            "add rule inet fwsimple input iif eth1 jump ZONE_IN_int comment \"\\\"Zone int\\\"\"", "add rule inet fwsimple output oif eth1 jump ZONE_OUT_int comment \"\\\"Zone int\\\"\"", "add rule inet fwsimple forward iif eth1 jump ZONE_FWD_int comment \"\\\"Zone int\\\"\"",
            "nft add rule inet fwsimple ZONE_IN_int ct state new tcp dport \"{ 1000-1024 }\" accept comment \\\"port_range.rule::allow_custom_range\\\"",
            "add rule inet fwsimple ZONE_IN_global return", "add rule inet fwsimple ZONE_OUT_global return", "add rule inet fwsimple ZONE_FWD_global return",
            "add rule inet fwsimple ZONE_IN_int return", "add rule inet fwsimple ZONE_OUT_int return", "add rule inet fwsimple ZONE_FWD_int return",
            "add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy drop ; }\"", # reject
            "add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
        ]
        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

    def test_scenario_ipv6_source_allow(self):
        zone_name = "int"
        config_content = self._get_config_one_zone(zone_name=zone_name, zone_def="eth1")
        rules_files = self._get_rules_ipv6_source_allow(zone_name=zone_name, port="22", source="2001:db8:cafe::100/128")

        expected_commands = [
            "flush ruleset", "add table inet fwsimple",
            "add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy accept ; }\"", "add chain inet fwsimple forward \"{ type filter hook forward priority 0 ; policy accept ; }\"", "add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
            "nft add rule inet fwsimple input iif lo accept comment \"\\\"Allow all loopback input\\\"\"", "nft add rule inet fwsimple output oif lo accept comment \"\\\"Allow all loopback output\\\"\"",
            "add rule inet fwsimple input ct state related,established accept", "add rule inet fwsimple output ct state related,established accept", "add rule inet fwsimple forward ct state related,established accept",
            "add rule inet fwsimple input ct state invalid drop", "add rule inet fwsimple forward ct state invalid drop",
            "nft add rule inet fwsimple input ip version 4 icmp type echo-request accept comment \"\\\"[ICMP] Echo Request\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code frag-needed accept comment \"\\\"[ICMP] Fragmentation needed\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code port-unreachable accept comment \"\\\"[ICMP] Port unreachable\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code host-unreachable accept comment \"\\\"[ICMP] Host unreachable\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp type source-quench accept comment \"\\\"[ICMP] Source Quench (RFC 792)\\\"\"",
            "nft add rule inet fwsimple input ip version 6 meta l4proto ipv6-nonxt accept comment \"\\\"[IPv6] No next header RFC2460\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type packet-too-big accept comment \"\\\"[ICMPv6] Packet too big\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type time-exceeded accept comment \"\\\"[ICMPv6] Time exceeded\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 133 accept comment \"\\\"[ICMPv6] Router sollicitation\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 134 accept comment \"\\\"[ICMPv6] Router advertisement\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 135 accept comment \"\\\"[ICMPv6] Neighbor sollicitation\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 136 accept comment \"\\\"[ICMPv6] Neighbor advertisement\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type echo-request accept comment \"\\\"[ICMPv6] Echo Request\\\"\"",
            "add chain inet fwsimple ZONE_IN_global", "add chain inet fwsimple ZONE_OUT_global", "add chain inet fwsimple ZONE_FWD_global",
            "add chain inet fwsimple ZONE_IN_int", "add chain inet fwsimple ZONE_OUT_int", "add chain inet fwsimple ZONE_FWD_int",
            "add rule inet fwsimple input jump ZONE_IN_global comment \"\\\"Zone global\\\"\"", "add rule inet fwsimple output jump ZONE_OUT_global comment \"\\\"Zone global\\\"\"", "add rule inet fwsimple forward jump ZONE_FWD_global comment \"\\\"Zone global\\\"\"",
            "add rule inet fwsimple input iif eth1 jump ZONE_IN_int comment \"\\\"Zone int\\\"\"", "add rule inet fwsimple output oif eth1 jump ZONE_OUT_int comment \"\\\"Zone int\\\"\"", "add rule inet fwsimple forward iif eth1 jump ZONE_FWD_int comment \"\\\"Zone int\\\"\"",
            "nft add rule inet fwsimple ZONE_IN_int ct state new tcp dport 22 ip6 saddr 2001:db8:cafe::100/128 accept comment \\\"ipv6_allow.rule::allow_ipv6_ssh\\\"",
            "add rule inet fwsimple ZONE_IN_global return", "add rule inet fwsimple ZONE_OUT_global return", "add rule inet fwsimple ZONE_FWD_global return",
            "add rule inet fwsimple ZONE_IN_int return", "add rule inet fwsimple ZONE_OUT_int return", "add rule inet fwsimple ZONE_FWD_int return",
            "add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy drop ; }\"", # reject
            "add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
        ]
        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

    def test_scenario_multiple_zones(self):
        config_content = self._get_config_multiple_zones()
        rules_files: Dict[str, str] = {}

        # Taken from old test_case_2_zone_expressions
        # Note: default policy in _get_config_multiple_zones is 'discard' for in/forward.
        # 'discard' translates to 'drop' for nftables base policy.
        expected_commands = [
            "flush ruleset", "add table inet fwsimple",
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
            "nft add rule inet fwsimple input ip version 4 icmp type echo-request accept comment \"\\\"[ICMP] Echo Request\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code frag-needed accept comment \"\\\"[ICMP] Fragmentation needed\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code port-unreachable accept comment \"\\\"[ICMP] Port unreachable\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code host-unreachable accept comment \"\\\"[ICMP] Host unreachable\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp type source-quench accept comment \"\\\"[ICMP] Source Quench (RFC 792)\\\"\"",
            "nft add rule inet fwsimple input ip version 6 meta l4proto ipv6-nonxt accept comment \"\\\"[IPv6] No next header RFC2460\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type packet-too-big accept comment \"\\\"[ICMPv6] Packet too big\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type time-exceeded accept comment \"\\\"[ICMPv6] Time exceeded\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 133 accept comment \"\\\"[ICMPv6] Router sollicitation\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 134 accept comment \"\\\"[ICMPv6] Router advertisement\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 135 accept comment \"\\\"[ICMPv6] Neighbor sollicitation\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 136 accept comment \"\\\"[ICMPv6] Neighbor advertisement\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type echo-request accept comment \"\\\"[ICMPv6] Echo Request\\\"\"",
            "add chain inet fwsimple ZONE_IN_global", "add chain inet fwsimple ZONE_OUT_global", "add chain inet fwsimple ZONE_FWD_global",
            "add chain inet fwsimple ZONE_IN_public", "add chain inet fwsimple ZONE_OUT_public", "add chain inet fwsimple ZONE_FWD_public",
            "add chain inet fwsimple ZONE_IN_private_lan", "add chain inet fwsimple ZONE_OUT_private_lan", "add chain inet fwsimple ZONE_FWD_private_lan",
            "add chain inet fwsimple ZONE_IN_guest_wifi", "add chain inet fwsimple ZONE_OUT_guest_wifi", "add chain inet fwsimple ZONE_FWD_guest_wifi",
            "add chain inet fwsimple ZONE_IN_vpn_users", "add chain inet fwsimple ZONE_OUT_vpn_users", "add chain inet fwsimple ZONE_FWD_vpn_users",
            "add chain inet fwsimple ZONE_IN_dmz_ipv6", "add chain inet fwsimple ZONE_OUT_dmz_ipv6", "add chain inet fwsimple ZONE_FWD_dmz_ipv6",
            "add rule inet fwsimple input jump ZONE_IN_global comment \"\\\"Zone global\\\"\"",
            "add rule inet fwsimple output jump ZONE_OUT_global comment \"\\\"Zone global\\\"\"",
            "add rule inet fwsimple forward jump ZONE_FWD_global comment \"\\\"Zone global\\\"\"",
            "nft add rule inet fwsimple input iif eth1 ip saddr 192.168.1.0/24 jump ZONE_IN_private_lan comment \"\\\"Zone private_lan\\\"\"",
            "nft add rule inet fwsimple output oif eth1 ip daddr 192.168.1.0/24 jump ZONE_OUT_private_lan comment \"\\\"Zone private_lan\\\"\"",
            "nft add rule inet fwsimple forward iif eth1 ip saddr 192.168.1.0/24 jump ZONE_FWD_private_lan comment \"\\\"Zone private_lan\\\"\"",
            "nft add rule inet fwsimple input iif eth1 ip saddr 192.168.2.0/24 jump ZONE_IN_guest_wifi comment \"\\\"Zone guest_wifi\\\"\"",
            "nft add rule inet fwsimple output oif eth1 ip daddr 192.168.2.0/24 jump ZONE_OUT_guest_wifi comment \"\\\"Zone guest_wifi\\\"\"",
            "nft add rule inet fwsimple forward iif eth1 ip saddr 192.168.2.0/24 jump ZONE_FWD_guest_wifi comment \"\\\"Zone guest_wifi\\\"\"",
            "nft add rule inet fwsimple input iif eth2 ip saddr 2001:db8:d320::/64 jump ZONE_IN_dmz_ipv6 comment \"\\\"Zone dmz_ipv6\\\"\"",
            "nft add rule inet fwsimple output oif eth2 ip daddr 2001:db8:d320::/64 jump ZONE_OUT_dmz_ipv6 comment \"\\\"Zone dmz_ipv6\\\"\"",
            "nft add rule inet fwsimple forward iif eth2 ip saddr 2001:db8:d320::/64 jump ZONE_FWD_dmz_ipv6 comment \"\\\"Zone dmz_ipv6\\\"\"",
            "nft add rule inet fwsimple input iif eth0 jump ZONE_IN_public comment \"\\\"Zone public\\\"\"",
            "nft add rule inet fwsimple output oif eth0 jump ZONE_OUT_public comment \"\\\"Zone public\\\"\"",
            "nft add rule inet fwsimple forward iif eth0 jump ZONE_FWD_public comment \"\\\"Zone public\\\"\"",
            "nft add rule inet fwsimple input iif tun0 jump ZONE_IN_vpn_users comment \"\\\"Zone vpn_users\\\"\"",
            "nft add rule inet fwsimple output oif tun0 jump ZONE_OUT_vpn_users comment \"\\\"Zone vpn_users\\\"\"",
            "nft add rule inet fwsimple forward iif tun0 jump ZONE_FWD_vpn_users comment \"\\\"Zone vpn_users\\\"\"",
            "add rule inet fwsimple ZONE_IN_global return", "add rule inet fwsimple ZONE_OUT_global return", "add rule inet fwsimple ZONE_FWD_global return",
            "add rule inet fwsimple ZONE_IN_public return", "add rule inet fwsimple ZONE_OUT_public return", "add rule inet fwsimple ZONE_FWD_public return",
            "add rule inet fwsimple ZONE_IN_private_lan return", "add rule inet fwsimple ZONE_OUT_private_lan return", "add rule inet fwsimple ZONE_FWD_private_lan return",
            "add rule inet fwsimple ZONE_IN_guest_wifi return", "add rule inet fwsimple ZONE_OUT_guest_wifi return", "add rule inet fwsimple ZONE_FWD_guest_wifi return",
            "add rule inet fwsimple ZONE_IN_vpn_users return", "add rule inet fwsimple ZONE_OUT_vpn_users return", "add rule inet fwsimple ZONE_FWD_vpn_users return",
            "add rule inet fwsimple ZONE_IN_dmz_ipv6 return", "add rule inet fwsimple ZONE_OUT_dmz_ipv6 return", "add rule inet fwsimple ZONE_FWD_dmz_ipv6 return",
            "add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy drop ; }\"", # discard
            "add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
            "add chain inet fwsimple forward \"{ type filter hook forward priority 0 ; policy drop ; }\"", # discard
        ]
        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

    # Placeholder for any parts of test_case_3_diverse_rules that are truly unique
    # and not covered by the scenarios above.
    # If all parts are covered, this can be removed.
    def test_nftables_specific_or_complex_rules(self):
        # This test will combine elements from the old test_case_3_diverse_rules
        # focusing on aspects not directly covered by the simpler scenarios,
        # or specific nftables interactions.
        # For example, mixed IPv4/IPv6 rules in the same file, specific ordering, etc.

        config_content = """
[fwsimple]
rulesets = %%RULESETS_DIR%%
engine = %%ENGINE_TYPE%%
[policy]
in = discard
out = accept
forward = discard
[zones]
ext = eth0
int = eth1
dmz = eth2:10.0.1.0/24
"""
        # Combining several rule types from the old test_case_3
        rules_files: Dict[str, str] = {
            "complex_rules.rule": """
[tcp_custom_app_range_to_int_logged]
zone = int
direction = in
protocol = tcp
port = 1000-1010
action = accept
log = true
multiport = true ; This is for iptables, nftables derives it

[reject_all_tcp_to_dmz_with_comment]
zone = dmz
direction = in
protocol = tcp
action = reject
comment = "Special DMZ reject rule"

[icmp6_ping_host_from_int_specific_type]
zone = int
direction = out
protocol = icmpv6
icmp_type = echo-request ; Example of a more specific icmp type if supported
destination = 2001:db8:dead::beef
action = accept
"""
        }

        # These expected commands are a SUBSET and ADAPTATION of the old test_case_3.
        # They focus on the specific rules defined above.
        # Full init/policy/zone commands are also needed.
        expected_commands = [
            "flush ruleset", "add table inet fwsimple",
            "add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy accept ; }\"", "add chain inet fwsimple forward \"{ type filter hook forward priority 0 ; policy accept ; }\"", "add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
            "nft add rule inet fwsimple input iif lo accept comment \"\\\"Allow all loopback input\\\"\"", "nft add rule inet fwsimple output oif lo accept comment \"\\\"Allow all loopback output\\\"\"",
            "add rule inet fwsimple input ct state related,established accept", "add rule inet fwsimple output ct state related,established accept", "add rule inet fwsimple forward ct state related,established accept",
            "add rule inet fwsimple input ct state invalid drop", "add rule inet fwsimple forward ct state invalid drop",
            "nft add rule inet fwsimple input ip version 4 icmp type echo-request accept comment \"\\\"[ICMP] Echo Request\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code frag-needed accept comment \"\\\"[ICMP] Fragmentation needed\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code port-unreachable accept comment \"\\\"[ICMP] Port unreachable\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp code host-unreachable accept comment \"\\\"[ICMP] Host unreachable\\\"\"", "nft add rule inet fwsimple input ip version 4 icmp type source-quench accept comment \"\\\"[ICMP] Source Quench (RFC 792)\\\"\"",
            "nft add rule inet fwsimple input ip version 6 meta l4proto ipv6-nonxt accept comment \"\\\"[IPv6] No next header RFC2460\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type packet-too-big accept comment \"\\\"[ICMPv6] Packet too big\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type time-exceeded accept comment \"\\\"[ICMPv6] Time exceeded\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 133 accept comment \"\\\"[ICMPv6] Router sollicitation\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 134 accept comment \"\\\"[ICMPv6] Router advertisement\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 135 accept comment \"\\\"[ICMPv6] Neighbor sollicitation\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type 136 accept comment \"\\\"[ICMPv6] Neighbor advertisement\\\"\"", "nft add rule inet fwsimple input ip version 6 icmpv6 type echo-request accept comment \"\\\"[ICMPv6] Echo Request\\\"\"",
            "add chain inet fwsimple ZONE_IN_global", "add chain inet fwsimple ZONE_OUT_global", "add chain inet fwsimple ZONE_FWD_global",
            "add chain inet fwsimple ZONE_IN_ext", "add chain inet fwsimple ZONE_OUT_ext", "add chain inet fwsimple ZONE_FWD_ext",
            "add chain inet fwsimple ZONE_IN_int", "add chain inet fwsimple ZONE_OUT_int", "add chain inet fwsimple ZONE_FWD_int",
            "add chain inet fwsimple ZONE_IN_dmz", "add chain inet fwsimple ZONE_OUT_dmz", "add chain inet fwsimple ZONE_FWD_dmz",
            "add rule inet fwsimple input jump ZONE_IN_global comment \"\\\"Zone global\\\"\"", "add rule inet fwsimple output jump ZONE_OUT_global comment \"\\\"Zone global\\\"\"", "add rule inet fwsimple forward jump ZONE_FWD_global comment \"\\\"Zone global\\\"\"",
            "nft add rule inet fwsimple input iif eth2 ip saddr 10.0.1.0/24 jump ZONE_IN_dmz comment \"\\\"Zone dmz\\\"\"", "nft add rule inet fwsimple output oif eth2 ip daddr 10.0.1.0/24 jump ZONE_OUT_dmz comment \"\\\"Zone dmz\\\"\"", "nft add rule inet fwsimple forward iif eth2 ip saddr 10.0.1.0/24 jump ZONE_FWD_dmz comment \"\\\"Zone dmz\\\"\"",
            "nft add rule inet fwsimple input iif eth0 jump ZONE_IN_ext comment \"\\\"Zone ext\\\"\"", "nft add rule inet fwsimple output oif eth0 jump ZONE_OUT_ext comment \"\\\"Zone ext\\\"\"", "nft add rule inet fwsimple forward iif eth0 jump ZONE_FWD_ext comment \"\\\"Zone ext\\\"\"",
            "nft add rule inet fwsimple input iif eth1 jump ZONE_IN_int comment \"\\\"Zone int\\\"\"", "nft add rule inet fwsimple output oif eth1 jump ZONE_OUT_int comment \"\\\"Zone int\\\"\"", "nft add rule inet fwsimple forward iif eth1 jump ZONE_FWD_int comment \"\\\"Zone int\\\"\"",
            # Rules from complex_rules.rule
            "nft add rule inet fwsimple ZONE_IN_dmz ct state new tcp reject comment \"complex_rules.rule::reject_all_tcp_to_dmz_with_comment\"",
            "nft add rule inet fwsimple ZONE_IN_int ct state new tcp dport \"{ 1000-1010 }\" log prefix \\\"complex_rules.rule::tcp_cu: \\\" accept comment \\\"complex_rules.rule::tcp_custom_app_range_to_int_logged\\\"",
            "nft add rule inet fwsimple ZONE_OUT_int ct state new icmpv6 type echo-request ip6 daddr 2001:db8:dead::beef/128 accept comment \\\"complex_rules.rule::icmp6_ping_host_from_int_specific_type\\\"",
            "add rule inet fwsimple ZONE_IN_global return", "add rule inet fwsimple ZONE_OUT_global return", "add rule inet fwsimple ZONE_FWD_global return",
            "add rule inet fwsimple ZONE_IN_ext return", "add rule inet fwsimple ZONE_OUT_ext return", "add rule inet fwsimple ZONE_FWD_ext return",
            "add rule inet fwsimple ZONE_IN_int return", "add rule inet fwsimple ZONE_OUT_int return", "add rule inet fwsimple ZONE_FWD_int return",
            "add rule inet fwsimple ZONE_IN_dmz return", "add rule inet fwsimple ZONE_OUT_dmz return", "add rule inet fwsimple ZONE_FWD_dmz return",
            "add chain inet fwsimple input \"{ type filter hook input priority 0 ; policy drop ; }\"", # discard
            "add chain inet fwsimple output \"{ type filter hook output priority 0 ; policy accept ; }\"",
            "add chain inet fwsimple forward \"{ type filter hook forward priority 0 ; policy drop ; }\"", # discard
        ]
        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

if __name__ == '__main__':
    unittest.main()
