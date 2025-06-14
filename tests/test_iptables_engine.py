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
    default_engine_in_config = 'iptables'

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

class TestIptablesEngine(IptablesTestCase): # Renamed from TestIptablesEngineBasic

    def test_scenario_basic_init(self):
        config_content = self._get_config_basic_init()
        rules_files: Dict[str, str] = {}

        # Adapted from old test_basic_init_and_default_policies
        # Default policies in _get_config_basic_init are: in=reject, out=accept, forward=drop
        expected_commands = [
            # From BASIC_IPTABLES_INIT (on both iptables and ip6tables)
            "-F",
            "-F",
            "-X",
            "-X",
            "-Z",
            "-Z",
            "-A INPUT -i lo -j ACCEPT",
            "-A INPUT -i lo -j ACCEPT",
            "-A OUTPUT -o lo -j ACCEPT",
            "-A OUTPUT -o lo -j ACCEPT",
            "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A INPUT -m conntrack --ctstate INVALID -j DROP",
            "-A INPUT -m conntrack --ctstate INVALID -j DROP",

            # From BASIC_IP4TABLES_INIT (iptables only)
            "-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT -m comment --comment \"[ICMP] Echo Request\"",
            "-A INPUT -p icmp -m icmp --icmp-type 3/4 -j ACCEPT -m comment --comment \"[ICMP] Fragmentation needed\"",
            "-A INPUT -p icmp -m icmp --icmp-type 3/3 -j ACCEPT -m comment --comment \"[ICMP] Port unreachable\"",
            "-A INPUT -p icmp -m icmp --icmp-type 3/1 -j ACCEPT -m comment --comment \"[ICMP] Host unreachable\"",
            "-A INPUT -p icmp -m icmp --icmp-type 4 -j ACCEPT -m comment --comment \"[ICMP] Source Quench (RFC 792)\"",

            # From BASIC_IP6TABLES_INIT (ip6tables only - normalized)
            "-A INPUT -p 59 -j ACCEPT -m comment --comment \"[IPv6] No next header RFC2460\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 2 -j ACCEPT -m comment --comment \"[ICMPv6] Packet too big\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 3 -j ACCEPT -m comment --comment \"[ICMPv6] Time exceeded\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 133 -j ACCEPT -m comment --comment \"[ICMPv6] Router sollicitation\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 134 -j ACCEPT -m comment --comment \"[ICMPv6] Router advertisement\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 135 -j ACCEPT -m comment --comment \"[ICMPv6] Neighbor sollicitation\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 136 -j ACCEPT -m comment --comment \"[ICMPv6] Neighbor advertisement\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 128 -j ACCEPT -m comment --comment \"[ICMPv6] Echo Request\"",

            # Zone Creation (global)
            "-N IN_global",
            "-N IN_global",
            "-N OUT_global",
            "-N OUT_global",
            "-N FWD_global",
            "-N FWD_global",

            # Zone Expression (global jump)
            "-A INPUT -m comment --comment \"Zone global\" -j IN_global",
            "-A INPUT -m comment --comment \"Zone global\" -j IN_global",
            "-A OUTPUT -m comment --comment \"Zone global\" -j OUT_global",
            "-A OUTPUT -m comment --comment \"Zone global\" -j OUT_global",
            "-A FORWARD -m comment --comment \"Zone global\" -j FWD_global",
            "-A FORWARD -m comment --comment \"Zone global\" -j FWD_global",

            # Zone Close (global return)
            "-A IN_global -j RETURN",
            "-A IN_global -j RETURN",
            "-A OUT_global -j RETURN",
            "-A OUT_global -j RETURN",
            "-A FWD_global -j RETURN",
            "-A FWD_global -j RETURN",

            # Default Policies
            "-P INPUT REJECT",
            "-P INPUT REJECT",
            "-P OUTPUT ACCEPT",
            "-P OUTPUT ACCEPT",
            "-P FORWARD DROP",
            "-P FORWARD DROP",
        ]

        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

    def test_scenario_tcp_allow(self):
        zone_name = "lan" # Defined in config by _get_config_one_zone
        config_content = self._get_config_one_zone(zone_name=zone_name, zone_def="eth0")
        rules_files = self._get_rules_tcp_allow(zone_name=zone_name, port="22", source="192.168.1.100/32")

        # Expected commands will include init, plus rules for the new TCP allow.
        # Default policies in _get_config_one_zone are: in=reject, out=accept, forward=drop
        expected_commands = [
            # Full Init Sequence (31 commands)
            # BASIC_IPTABLES_INIT (9 rules * 2 versions = 18 commands, less -P rules)
            "-F",
            "-F", # ip6tables
            "-X",
            "-X", # ip6tables
            "-Z",
            "-Z", # ip6tables
            "-A INPUT -i lo -j ACCEPT",
            "-A INPUT -i lo -j ACCEPT", # ip6tables
            "-A OUTPUT -o lo -j ACCEPT",
            "-A OUTPUT -o lo -j ACCEPT", # ip6tables
            "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", # ip6tables
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", # ip6tables
            "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", # ip6tables
            "-A INPUT -m conntrack --ctstate INVALID -j DROP",
            "-A INPUT -m conntrack --ctstate INVALID -j DROP", # ip6tables
            # BASIC_IP4TABLES_INIT (5 rules, iptables only)
            "-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT -m comment --comment \"[ICMP] Echo Request\"",
            "-A INPUT -p icmp -m icmp --icmp-type 3/4 -j ACCEPT -m comment --comment \"[ICMP] Fragmentation needed\"",
            "-A INPUT -p icmp -m icmp --icmp-type 3/3 -j ACCEPT -m comment --comment \"[ICMP] Port unreachable\"",
            "-A INPUT -p icmp -m icmp --icmp-type 3/1 -j ACCEPT -m comment --comment \"[ICMP] Host unreachable\"",
            "-A INPUT -p icmp -m icmp --icmp-type 4 -j ACCEPT -m comment --comment \"[ICMP] Source Quench (RFC 792)\"",
            # BASIC_IP6TABLES_INIT (8 rules, ip6tables only, normalized)
            "-A INPUT -p 59 -j ACCEPT -m comment --comment \"[IPv6] No next header RFC2460\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 2 -j ACCEPT -m comment --comment \"[ICMPv6] Packet too big\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 3 -j ACCEPT -m comment --comment \"[ICMPv6] Time exceeded\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 133 -j ACCEPT -m comment --comment \"[ICMPv6] Router sollicitation\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 134 -j ACCEPT -m comment --comment \"[ICMPv6] Router advertisement\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 135 -j ACCEPT -m comment --comment \"[ICMPv6] Neighbor sollicitation\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 136 -j ACCEPT -m comment --comment \"[ICMPv6] Neighbor advertisement\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 128 -j ACCEPT -m comment --comment \"[ICMPv6] Echo Request\"",

            # Zone Creation for global (3*2=6) and lan (3*2=6) = 12 commands
            "-N IN_global", "-N OUT_global", "-N FWD_global",
            "-N IN_global", "-N OUT_global", "-N FWD_global", # ip6tables
            "-N IN_lan", "-N OUT_lan", "-N FWD_lan",
            "-N IN_lan", "-N OUT_lan", "-N FWD_lan", # ip6tables

            # Zone Expression Jumps for global (3*2=6) and lan (3*2=6) = 12 commands
            "-A INPUT -m comment --comment \"Zone global\" -j IN_global",
            "-A OUTPUT -m comment --comment \"Zone global\" -j OUT_global",
            "-A FORWARD -m comment --comment \"Zone global\" -j FWD_global",
            "-A INPUT -m comment --comment \"Zone global\" -j IN_global", # ip6tables
            "-A OUTPUT -m comment --comment \"Zone global\" -j OUT_global", # ip6tables
            "-A FORWARD -m comment --comment \"Zone global\" -j FWD_global", # ip6tables
            "-A INPUT -m comment --comment \"Zone lan\" -i eth0 -j IN_lan",
            "-A OUTPUT -m comment --comment \"Zone lan\" -o eth0 -j OUT_lan",
            "-A FORWARD -m comment --comment \"Zone lan\" -i eth0 -j FWD_lan",
            "-A INPUT -m comment --comment \"Zone lan\" -i eth0 -j IN_lan", # ip6tables
            "-A OUTPUT -m comment --comment \"Zone lan\" -o eth0 -j OUT_lan", # ip6tables
            "-A FORWARD -m comment --comment \"Zone lan\" -i eth0 -j FWD_lan", # ip6tables

            # Specific TCP Allow Rule (1 command, applied to IPv4 chain IN_lan)
            "-A IN_lan -m conntrack --ctstate NEW -m comment --comment \"tcp_allow.rule::allow_ssh_from_host\" -p tcp --dport 22 -s 192.168.1.100/32 -j ACCEPT",

            # Zone Close for global (3*2=6) and lan (3*2=6) = 12 commands
            "-A IN_global -j RETURN", "-A OUT_global -j RETURN", "-A FWD_global -j RETURN",
            "-A IN_global -j RETURN", # ip6tables
            "-A OUT_global -j RETURN", # ip6tables
            "-A FWD_global -j RETURN", # ip6tables
            "-A IN_lan -j RETURN",
            "-A IN_lan -j RETURN", # ip6tables
            "-A OUT_lan -j RETURN",
            "-A OUT_lan -j RETURN", # ip6tables
            "-A FWD_lan -j RETURN",
            "-A FWD_lan -j RETURN", # ip6tables

            # Final Default Policies (6 commands)
            # Config: in=reject, out=accept, forward=drop
            "-P INPUT REJECT",
            "-P INPUT REJECT", # ip6tables
            "-P OUTPUT ACCEPT",
            "-P OUTPUT ACCEPT", # ip6tables
            "-P FORWARD DROP",
            "-P FORWARD DROP"  # ip6tables
        ]
        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

    def test_scenario_udp_deny(self):
        # Default policies in _get_config_one_zone: in=reject, out=accept, forward=drop
        # Rule: out, udp, dport 53, dest 8.8.8.8, action=discard
        self.skipTest("TODO: Define expected iptables commands for UDP deny scenario")

    def test_scenario_logged_rule(self):
        self.skipTest("TODO: Define expected iptables commands for logged rule scenario")

    def test_scenario_multiple_ports(self):
        self.skipTest("TODO: Define expected iptables commands for multiple ports scenario")

    def test_scenario_port_range(self):
        self.skipTest("TODO: Define expected iptables commands for port range scenario")

    def test_scenario_ipv6_source_allow(self):
        zone_name = "lan6"
        config_content = self._get_config_one_zone(zone_name=zone_name, zone_def="eth1") # config has in=reject
        rules_files = self._get_rules_ipv6_source_allow(zone_name=zone_name, port="22", source="2001:db8:cafe::100/128")

        expected_commands = [
            # Full Init Sequence (31 commands)
            # BASIC_IPTABLES_INIT (9 rules, applied to both ip4/ip6, normalized)
            "-F",
            "-F",
            "-X",
            "-X",
            "-Z",
            "-Z",
            "-A INPUT -i lo -j ACCEPT",
            "-A INPUT -i lo -j ACCEPT",
            "-A OUTPUT -o lo -j ACCEPT",
            "-A OUTPUT -o lo -j ACCEPT",
            "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A INPUT -m conntrack --ctstate INVALID -j DROP",
            "-A INPUT -m conntrack --ctstate INVALID -j DROP",
            # BASIC_IP4TABLES_INIT (5 rules, iptables only, normalized)
            "-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT -m comment --comment \"[ICMP] Echo Request\"",
            "-A INPUT -p icmp -m icmp --icmp-type 3/4 -j ACCEPT -m comment --comment \"[ICMP] Fragmentation needed\"",
            "-A INPUT -p icmp -m icmp --icmp-type 3/3 -j ACCEPT -m comment --comment \"[ICMP] Port unreachable\"",
            "-A INPUT -p icmp -m icmp --icmp-type 3/1 -j ACCEPT -m comment --comment \"[ICMP] Host unreachable\"",
            "-A INPUT -p icmp -m icmp --icmp-type 4 -j ACCEPT -m comment --comment \"[ICMP] Source Quench (RFC 792)\"",
            # BASIC_IP6TABLES_INIT (8 rules, ip6tables only, normalized)
            "-A INPUT -p 59 -j ACCEPT -m comment --comment \"[IPv6] No next header RFC2460\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 2 -j ACCEPT -m comment --comment \"[ICMPv6] Packet too big\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 3 -j ACCEPT -m comment --comment \"[ICMPv6] Time exceeded\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 133 -j ACCEPT -m comment --comment \"[ICMPv6] Router sollicitation\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 134 -j ACCEPT -m comment --comment \"[ICMPv6] Router advertisement\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 135 -j ACCEPT -m comment --comment \"[ICMPv6] Neighbor sollicitation\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 136 -j ACCEPT -m comment --comment \"[ICMPv6] Neighbor advertisement\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 128 -j ACCEPT -m comment --comment \"[ICMPv6] Echo Request\"",

            # Global Zone Setup (18 commands)
            "-N IN_global", "-N IN_global",
            "-N OUT_global", "-N OUT_global",
            "-N FWD_global", "-N FWD_global",
            "-A INPUT -m comment --comment \"Zone global\" -j IN_global",
            "-A INPUT -m comment --comment \"Zone global\" -j IN_global",
            "-A OUTPUT -m comment --comment \"Zone global\" -j OUT_global",
            "-A OUTPUT -m comment --comment \"Zone global\" -j OUT_global",
            "-A FORWARD -m comment --comment \"Zone global\" -j FWD_global",
            "-A FORWARD -m comment --comment \"Zone global\" -j FWD_global",
            "-A IN_global -j RETURN",
            "-A IN_global -j RETURN",
            "-A OUT_global -j RETURN",
            "-A OUT_global -j RETURN",
            "-A FWD_global -j RETURN",
            "-A FWD_global -j RETURN",

            # LAN6 Zone Setup (18 commands for zone 'lan6' on 'eth1')
            "-N IN_lan6", "-N IN_lan6",
            "-N OUT_lan6", "-N OUT_lan6",
            "-N FWD_lan6", "-N FWD_lan6",
            "-A INPUT -m comment --comment \"Zone lan6\" -i eth1 -j IN_lan6",
            "-A INPUT -m comment --comment \"Zone lan6\" -i eth1 -j IN_lan6",
            "-A OUTPUT -m comment --comment \"Zone lan6\" -o eth1 -j OUT_lan6",
            "-A OUTPUT -m comment --comment \"Zone lan6\" -o eth1 -j OUT_lan6",
            "-A FORWARD -m comment --comment \"Zone lan6\" -i eth1 -j FWD_lan6",
            "-A FORWARD -m comment --comment \"Zone lan6\" -i eth1 -j FWD_lan6",
            "-A IN_lan6 -j RETURN",
            "-A IN_lan6 -j RETURN",
            "-A OUT_lan6 -j RETURN",
            "-A OUT_lan6 -j RETURN",
            "-A FWD_lan6 -j RETURN",
            "-A FWD_lan6 -j RETURN",

            # Specific IPv6 Allow Rule (1 command, applied to ip6tables chain IN_lan6)
            # This command should be prefixed with "ip6tables " by the engine, but normalized here.
            "-A IN_lan6 -m conntrack --ctstate NEW -m comment --comment \"ipv6_allow.rule::allow_ipv6_ssh\" -p tcp --dport 22 -s 2001:db8:cafe::100/128 -j ACCEPT",

            # Final Default Policies (6 commands)
            # Config: in=reject, out=accept, forward=drop (from _get_config_one_zone)
            "-P INPUT REJECT",
            "-P INPUT REJECT",
            "-P OUTPUT ACCEPT",
            "-P OUTPUT ACCEPT",
            "-P FORWARD DROP",
            "-P FORWARD DROP"
        ]
        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

    def test_scenario_multiple_zones(self):
        # Config: public=eth0, private_lan=eth1:192.168.1.0/24, guest_wifi=eth1:192.168.2.0/24,
        #         vpn_users=tun0, dmz_ipv6=eth2:2001:db8:d320::/64
        # Policy: in=discard, out=accept, forward=discard
        config_content = self._get_config_multiple_zones()
        rules_files: Dict[str, str] = {}

        expected_commands = [
            # == Global Init Rules ==
            # BASIC_IPTABLES_INIT (applied to iptables) - 9 rules
            "-F",
            "-X",
            "-Z",
            "-A INPUT -i lo -j ACCEPT",
            "-A OUTPUT -o lo -j ACCEPT",
            "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A INPUT -m conntrack --ctstate INVALID -j DROP",

            # BASIC_IP4TABLES_INIT (applied to iptables) - 5 rules
            "-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT -m comment --comment \"[ICMP] Echo Request\"",
            "-A INPUT -p icmp -m icmp --icmp-type 3/4 -j ACCEPT -m comment --comment \"[ICMP] Fragmentation needed\"",
            "-A INPUT -p icmp -m icmp --icmp-type 3/3 -j ACCEPT -m comment --comment \"[ICMP] Port unreachable\"",
            "-A INPUT -p icmp -m icmp --icmp-type 3/1 -j ACCEPT -m comment --comment \"[ICMP] Host unreachable\"",
            "-A INPUT -p icmp -m icmp --icmp-type 4 -j ACCEPT -m comment --comment \"[ICMP] Source Quench (RFC 792)\"",

            # BASIC_IPTABLES_INIT (applied to ip6tables) - 9 rules
            "-F",
            "-X",
            "-Z",
            "-A INPUT -i lo -j ACCEPT",
            "-A OUTPUT -o lo -j ACCEPT",
            "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A INPUT -m conntrack --ctstate INVALID -j DROP",

            # BASIC_IP6TABLES_INIT (applied to ip6tables) - 8 rules
            "-A INPUT -p 59 -j ACCEPT -m comment --comment \"[IPv6] No next header RFC2460\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 2 -j ACCEPT -m comment --comment \"[ICMPv6] Packet too big\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 3 -j ACCEPT -m comment --comment \"[ICMPv6] Time exceeded\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 133 -j ACCEPT -m comment --comment \"[ICMPv6] Router sollicitation\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 134 -j ACCEPT -m comment --comment \"[ICMPv6] Router advertisement\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 135 -j ACCEPT -m comment --comment \"[ICMPv6] Neighbor sollicitation\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 136 -j ACCEPT -m comment --comment \"[ICMPv6] Neighbor advertisement\"",
            "-A INPUT -p icmpv6 -m icmpv6 --icmpv6-type 128 -j ACCEPT -m comment --comment \"[ICMPv6] Echo Request\"",

            # Global Zone chains (iptables, then ip6tables)
            "-N IN_global", "-N OUT_global", "-N FWD_global",
            "-N IN_global", "-N OUT_global", "-N FWD_global",
            # Public Zone chains
            "-N IN_public", "-N OUT_public", "-N FWD_public",
            "-N IN_public", "-N OUT_public", "-N FWD_public",
            # Private LAN Zone chains
            "-N IN_private_lan", "-N OUT_private_lan", "-N FWD_private_lan",
            "-N IN_private_lan", "-N OUT_private_lan", "-N FWD_private_lan",
            # Guest WiFi Zone chains
            "-N IN_guest_wifi", "-N OUT_guest_wifi", "-N FWD_guest_wifi",
            "-N IN_guest_wifi", "-N OUT_guest_wifi", "-N FWD_guest_wifi",
            # VPN Users Zone chains
            "-N IN_vpn_users", "-N OUT_vpn_users", "-N FWD_vpn_users",
            "-N IN_vpn_users", "-N OUT_vpn_users", "-N FWD_vpn_users",
            # DMZ IPv6 Zone chains
            "-N IN_dmz_ipv6", "-N OUT_dmz_ipv6", "-N FWD_dmz_ipv6",
            "-N IN_dmz_ipv6", "-N OUT_dmz_ipv6", "-N FWD_dmz_ipv6",

            # Global (no interface/IP, so simple jump) - 3 jumps * 2 IP versions = 6
            "-A INPUT -m comment --comment \"Zone global\" -j IN_global",
            "-A OUTPUT -m comment --comment \"Zone global\" -j OUT_global",
            "-A FORWARD -m comment --comment \"Zone global\" -j FWD_global",
            "-A INPUT -m comment --comment \"Zone global\" -j IN_global",
            "-A OUTPUT -m comment --comment \"Zone global\" -j OUT_global",
            "-A FORWARD -m comment --comment \"Zone global\" -j FWD_global",

            # Private LAN (eth1:192.168.1.0/24) - IPv4 only - 3 jumps
            "-A INPUT -i eth1 -s 192.168.1.0/24 -m comment --comment \"Zone private_lan\" -j IN_private_lan",
            "-A OUTPUT -o eth1 -d 192.168.1.0/24 -m comment --comment \"Zone private_lan\" -j OUT_private_lan",
            "-A FORWARD -i eth1 -s 192.168.1.0/24 -m comment --comment \"Zone private_lan\" -j FWD_private_lan",

            # Guest WiFi (eth1:192.168.2.0/24) - IPv4 only - 3 jumps
            "-A INPUT -i eth1 -s 192.168.2.0/24 -m comment --comment \"Zone guest_wifi\" -j IN_guest_wifi",
            "-A OUTPUT -o eth1 -d 192.168.2.0/24 -m comment --comment \"Zone guest_wifi\" -j OUT_guest_wifi",
            "-A FORWARD -i eth1 -s 192.168.2.0/24 -m comment --comment \"Zone guest_wifi\" -j FWD_guest_wifi",

            # DMZ IPv6 (eth2:2001:db8:d320::/64) - IPv6 only - 3 jumps
            "-A INPUT -i eth2 -s 2001:db8:d320::/64 -m comment --comment \"Zone dmz_ipv6\" -j IN_dmz_ipv6",
            "-A OUTPUT -o eth2 -d 2001:db8:d320::/64 -m comment --comment \"Zone dmz_ipv6\" -j OUT_dmz_ipv6",
            "-A FORWARD -i eth2 -s 2001:db8:d320::/64 -m comment --comment \"Zone dmz_ipv6\" -j FWD_dmz_ipv6",

            # Public (eth0) - Both IPv4 and IPv6 - 3 jumps * 2 IP versions = 6
            "-A INPUT -i eth0 -m comment --comment \"Zone public\" -j IN_public",
            "-A OUTPUT -o eth0 -m comment --comment \"Zone public\" -j OUT_public",
            "-A FORWARD -i eth0 -m comment --comment \"Zone public\" -j FWD_public",
            "-A INPUT -i eth0 -m comment --comment \"Zone public\" -j IN_public",
            "-A OUTPUT -o eth0 -m comment --comment \"Zone public\" -j OUT_public",
            "-A FORWARD -i eth0 -m comment --comment \"Zone public\" -j FWD_public",

            # VPN Users (tun0) - Both IPv4 and IPv6 - 3 jumps * 2 IP versions = 6
            "-A INPUT -i tun0 -m comment --comment \"Zone vpn_users\" -j IN_vpn_users",
            "-A OUTPUT -o tun0 -m comment --comment \"Zone vpn_users\" -j OUT_vpn_users",
            "-A FORWARD -i tun0 -m comment --comment \"Zone vpn_users\" -j FWD_vpn_users",
            "-A INPUT -i tun0 -m comment --comment \"Zone vpn_users\" -j IN_vpn_users",
            "-A OUTPUT -o tun0 -m comment --comment \"Zone vpn_users\" -j OUT_vpn_users",
            "-A FORWARD -i tun0 -m comment --comment \"Zone vpn_users\" -j FWD_vpn_users",

            "-A IN_global -j RETURN", "-A OUT_global -j RETURN", "-A FWD_global -j RETURN",
            "-A IN_global -j RETURN", "-A OUT_global -j RETURN", "-A FWD_global -j RETURN",
            "-A IN_public -j RETURN", "-A OUT_public -j RETURN", "-A FWD_public -j RETURN",
            "-A IN_public -j RETURN", "-A OUT_public -j RETURN", "-A FWD_public -j RETURN",
            "-A IN_private_lan -j RETURN", "-A OUT_private_lan -j RETURN", "-A FWD_private_lan -j RETURN",
            "-A IN_private_lan -j RETURN", "-A OUT_private_lan -j RETURN", "-A FWD_private_lan -j RETURN",
            "-A IN_guest_wifi -j RETURN", "-A OUT_guest_wifi -j RETURN", "-A FWD_guest_wifi -j RETURN",
            "-A IN_guest_wifi -j RETURN", "-A OUT_guest_wifi -j RETURN", "-A FWD_guest_wifi -j RETURN",
            "-A IN_vpn_users -j RETURN", "-A OUT_vpn_users -j RETURN", "-A FWD_vpn_users -j RETURN",
            "-A IN_vpn_users -j RETURN", "-A OUT_vpn_users -j RETURN", "-A FWD_vpn_users -j RETURN",
            "-A IN_dmz_ipv6 -j RETURN", "-A OUT_dmz_ipv6 -j RETURN", "-A FWD_dmz_ipv6 -j RETURN",
            "-A IN_dmz_ipv6 -j RETURN", "-A OUT_dmz_ipv6 -j RETURN", "-A FWD_dmz_ipv6 -j RETURN",

            "-P INPUT DROP",
            "-P FORWARD DROP",
            "-P OUTPUT ACCEPT",
            "-P INPUT DROP",
            "-P FORWARD DROP",
            "-P OUTPUT ACCEPT",
        ]
        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

if __name__ == '__main__':
    unittest.main()
