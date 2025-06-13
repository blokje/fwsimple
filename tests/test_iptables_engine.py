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

class TestIptablesEngine(IptablesTestCase): # Renamed from TestIptablesEngineBasic

    def test_scenario_basic_init(self):
        config_content = self._get_config_basic_init()
        rules_files: Dict[str, str] = {}

        # Adapted from old test_basic_init_and_default_policies
        # Default policies in _get_config_basic_init are: in=reject, out=accept, forward=drop
        expected_commands = [
            # IPv4 commands
            "-P INPUT ACCEPT", # Initial policy before dropping/rejecting
            "-P FORWARD ACCEPT",
            "-P OUTPUT ACCEPT",
            "-F INPUT", "-F FORWARD", "-F OUTPUT", "-X", "-Z", # Flush, Delete, Zero
            "-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "-A INPUT -i lo -j ACCEPT",
            "-A OUTPUT -o lo -j ACCEPT",
            "-A INPUT -m state --state INVALID -j DROP",
            "-A FORWARD -m state --state INVALID -j DROP",
            "-A INPUT -p icmp --icmp-type echo-request -j ACCEPT", # Basic ICMP
            # Default policies applied at the end
            "-P INPUT REJECT", # from config
            "-P FORWARD DROP",   # from config
            "-P OUTPUT ACCEPT",  # from config

            # IPv6 commands (ip6tables)
            "-P INPUT ACCEPT", "-P FORWARD ACCEPT", "-P OUTPUT ACCEPT",
            "-F INPUT", "-F FORWARD", "-F OUTPUT", "-X", "-Z",
            "-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "-A INPUT -i lo -j ACCEPT",
            "-A OUTPUT -o lo -j ACCEPT",
            "-A INPUT -m state --state INVALID -j DROP",
            "-A FORWARD -m state --state INVALID -j DROP",
            "-A INPUT -p icmpv6 --icmpv6-type echo-request -j ACCEPT", # Basic ICMPv6
            "-P INPUT REJECT",
            "-P FORWARD DROP",
            "-P OUTPUT ACCEPT",
        ]

        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

    def test_scenario_tcp_allow(self):
        zone_name = "lan" # Defined in config by _get_config_one_zone
        config_content = self._get_config_one_zone(zone_name=zone_name, zone_def="eth0")
        rules_files = self._get_rules_tcp_allow(zone_name=zone_name, port="22", source="192.168.1.100/32")

        # Expected commands will include init, plus rules for the new TCP allow.
        # Base init commands (simplified, assuming default policies from _get_config_one_zone: in=reject, out=accept, forward=drop)
        expected_commands = [
            # IPv4 Init
            "-P INPUT ACCEPT", "-P FORWARD ACCEPT", "-P OUTPUT ACCEPT",
            "-F INPUT", "-F FORWARD", "-F OUTPUT", "-X", "-Z",
            "-N ZONE_GLOBAL_INPUT", "-N ZONE_GLOBAL_OUTPUT", "-N ZONE_GLOBAL_FORWARD", # Chains for global zone
            "-N ZONE_LAN_INPUT", "-N ZONE_LAN_OUTPUT", "-N ZONE_LAN_FORWARD",       # Chains for lan zone
            "-A INPUT -j ZONE_GLOBAL_INPUT",
            "-A OUTPUT -j ZONE_GLOBAL_OUTPUT",
            "-A FORWARD -j ZONE_GLOBAL_FORWARD",
            "-A INPUT -i eth0 -j ZONE_LAN_INPUT", # lan zone jump
            "-A OUTPUT -o eth0 -j ZONE_LAN_OUTPUT",
            "-A FORWARD -i eth0 -j ZONE_LAN_FORWARD", # Assuming forward also uses input interface for zone match
            # Standard rules in global
            "-A ZONE_GLOBAL_INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "-A ZONE_GLOBAL_OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "-A ZONE_GLOBAL_FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "-A ZONE_GLOBAL_INPUT -i lo -j ACCEPT",
            "-A ZONE_GLOBAL_OUTPUT -o lo -j ACCEPT",
            "-A ZONE_GLOBAL_INPUT -m state --state INVALID -j DROP",
            "-A ZONE_GLOBAL_FORWARD -m state --state INVALID -j DROP",
            "-A ZONE_GLOBAL_INPUT -p icmp --icmp-type echo-request -j ACCEPT",
            # TCP Allow rule in lan zone
            "-A ZONE_LAN_INPUT -p tcp -s 192.168.1.100/32 --dport 22 -m state --state NEW -j ACCEPT -m comment --comment \"tcp_allow.rule::allow_ssh_from_host\"",
             # Zone returns
            "-A ZONE_GLOBAL_INPUT -j RETURN", "-A ZONE_GLOBAL_OUTPUT -j RETURN", "-A ZONE_GLOBAL_FORWARD -j RETURN",
            "-A ZONE_LAN_INPUT -j RETURN", "-A ZONE_LAN_OUTPUT -j RETURN", "-A ZONE_LAN_FORWARD -j RETURN",
            # Default policies
            "-P INPUT REJECT", "-P FORWARD DROP", "-P OUTPUT ACCEPT",

            # IPv6 Init (similar structure)
            "ip6tables -P INPUT ACCEPT", "ip6tables -P FORWARD ACCEPT", "ip6tables -P OUTPUT ACCEPT",
            "ip6tables -F INPUT", "ip6tables -F FORWARD", "ip6tables -F OUTPUT", "ip6tables -X", "ip6tables -Z",
            "ip6tables -N ZONE_GLOBAL_INPUT", "ip6tables -N ZONE_GLOBAL_OUTPUT", "ip6tables -N ZONE_GLOBAL_FORWARD",
            "ip6tables -N ZONE_LAN_INPUT", "ip6tables -N ZONE_LAN_OUTPUT", "ip6tables -N ZONE_LAN_FORWARD",
            "ip6tables -A INPUT -j ZONE_GLOBAL_INPUT",
            "ip6tables -A OUTPUT -j ZONE_GLOBAL_OUTPUT",
            "ip6tables -A FORWARD -j ZONE_GLOBAL_FORWARD",
            "ip6tables -A INPUT -i eth0 -j ZONE_LAN_INPUT",
            "ip6tables -A OUTPUT -o eth0 -j ZONE_LAN_OUTPUT",
            "ip6tables -A FORWARD -i eth0 -j ZONE_LAN_FORWARD",
            "ip6tables -A ZONE_GLOBAL_INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "ip6tables -A ZONE_GLOBAL_OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "ip6tables -A ZONE_GLOBAL_FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "ip6tables -A ZONE_GLOBAL_INPUT -i lo -j ACCEPT",
            "ip6tables -A ZONE_GLOBAL_OUTPUT -o lo -j ACCEPT",
            "ip6tables -A ZONE_GLOBAL_INPUT -m state --state INVALID -j DROP",
            "ip6tables -A ZONE_GLOBAL_FORWARD -m state --state INVALID -j DROP",
            "ip6tables -A ZONE_GLOBAL_INPUT -p icmpv6 --icmpv6-type echo-request -j ACCEPT",
            # No IPv6 rule for an IPv4 source
            "ip6tables -A ZONE_GLOBAL_INPUT -j RETURN", "ip6tables -A ZONE_GLOBAL_OUTPUT -j RETURN", "ip6tables -A ZONE_GLOBAL_FORWARD -j RETURN",
            "ip6tables -A ZONE_LAN_INPUT -j RETURN", "ip6tables -A ZONE_LAN_OUTPUT -j RETURN", "ip6tables -A ZONE_LAN_FORWARD -j RETURN",
            "ip6tables -P INPUT REJECT", "ip6tables -P FORWARD DROP", "ip6tables -P OUTPUT ACCEPT",
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
            # IPv4 Init (No IPv6 rule here)
            "-P INPUT ACCEPT", "-P FORWARD ACCEPT", "-P OUTPUT ACCEPT",
            "-F INPUT", "-F FORWARD", "-F OUTPUT", "-X", "-Z",
            "-N ZONE_GLOBAL_INPUT", "-N ZONE_GLOBAL_OUTPUT", "-N ZONE_GLOBAL_FORWARD",
            "-N ZONE_LAN6_INPUT", "-N ZONE_LAN6_OUTPUT", "-N ZONE_LAN6_FORWARD",
            "-A INPUT -j ZONE_GLOBAL_INPUT", "-A OUTPUT -j ZONE_GLOBAL_OUTPUT", "-A FORWARD -j ZONE_GLOBAL_FORWARD",
            "-A INPUT -i eth1 -j ZONE_LAN6_INPUT",
            "-A OUTPUT -o eth1 -j ZONE_LAN6_OUTPUT",
            "-A FORWARD -i eth1 -j ZONE_LAN6_FORWARD",
            "-A ZONE_GLOBAL_INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "-A ZONE_GLOBAL_OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "-A ZONE_GLOBAL_FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "-A ZONE_GLOBAL_INPUT -i lo -j ACCEPT", "-A ZONE_GLOBAL_OUTPUT -o lo -j ACCEPT",
            "-A ZONE_GLOBAL_INPUT -m state --state INVALID -j DROP",
            "-A ZONE_GLOBAL_FORWARD -m state --state INVALID -j DROP",
            "-A ZONE_GLOBAL_INPUT -p icmp --icmp-type echo-request -j ACCEPT",
            "-A ZONE_GLOBAL_INPUT -j RETURN", "-A ZONE_GLOBAL_OUTPUT -j RETURN", "-A ZONE_GLOBAL_FORWARD -j RETURN",
            "-A ZONE_LAN6_INPUT -j RETURN", "-A ZONE_LAN6_OUTPUT -j RETURN", "-A ZONE_LAN6_FORWARD -j RETURN",
            "-P INPUT REJECT", "-P FORWARD DROP", "-P OUTPUT ACCEPT",

            # IPv6 Init
            "ip6tables -P INPUT ACCEPT", "ip6tables -P FORWARD ACCEPT", "ip6tables -P OUTPUT ACCEPT",
            "ip6tables -F INPUT", "ip6tables -F FORWARD", "ip6tables -F OUTPUT", "ip6tables -X", "ip6tables -Z",
            "ip6tables -N ZONE_GLOBAL_INPUT", "ip6tables -N ZONE_GLOBAL_OUTPUT", "ip6tables -N ZONE_GLOBAL_FORWARD",
            "ip6tables -N ZONE_LAN6_INPUT", "ip6tables -N ZONE_LAN6_OUTPUT", "ip6tables -N ZONE_LAN6_FORWARD",
            "ip6tables -A INPUT -j ZONE_GLOBAL_INPUT",
            "ip6tables -A OUTPUT -j ZONE_GLOBAL_OUTPUT",
            "ip6tables -A FORWARD -j ZONE_GLOBAL_FORWARD",
            "ip6tables -A INPUT -i eth1 -j ZONE_LAN6_INPUT",
            "ip6tables -A OUTPUT -o eth1 -j ZONE_LAN6_OUTPUT",
            "ip6tables -A FORWARD -i eth1 -j ZONE_LAN6_FORWARD",
            "ip6tables -A ZONE_GLOBAL_INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "ip6tables -A ZONE_GLOBAL_OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "ip6tables -A ZONE_GLOBAL_FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "ip6tables -A ZONE_GLOBAL_INPUT -i lo -j ACCEPT",
            "ip6tables -A ZONE_GLOBAL_OUTPUT -o lo -j ACCEPT",
            "ip6tables -A ZONE_GLOBAL_INPUT -m state --state INVALID -j DROP",
            "ip6tables -A ZONE_GLOBAL_FORWARD -m state --state INVALID -j DROP",
            "ip6tables -A ZONE_GLOBAL_INPUT -p icmpv6 --icmpv6-type echo-request -j ACCEPT",
            # IPv6 rule applied to ZONE_LAN6_INPUT
            "ip6tables -A ZONE_LAN6_INPUT -p tcp -s 2001:db8:cafe::100/128 --dport 22 -m state --state NEW -j ACCEPT -m comment --comment \"ipv6_allow.rule::allow_ipv6_ssh\"",
            "ip6tables -A ZONE_GLOBAL_INPUT -j RETURN", "ip6tables -A ZONE_GLOBAL_OUTPUT -j RETURN", "ip6tables -A ZONE_GLOBAL_FORWARD -j RETURN",
            "ip6tables -A ZONE_LAN6_INPUT -j RETURN", "ip6tables -A ZONE_LAN6_OUTPUT -j RETURN", "ip6tables -A ZONE_LAN6_FORWARD -j RETURN",
            "ip6tables -P INPUT REJECT", "ip6tables -P FORWARD DROP", "ip6tables -P OUTPUT ACCEPT",
        ]
        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

    def test_scenario_multiple_zones(self):
        # Config: public=eth0, private_lan=eth1:192.168.1.0/24, guest_wifi=eth1:192.168.2.0/24,
        #         vpn_users=tun0, dmz_ipv6=eth2:2001:db8:dmz::/64
        # Policy: in=discard, out=accept, forward=discard
        config_content = self._get_config_multiple_zones()
        rules_files: Dict[str, str] = {}

        expected_commands = [
            # IPv4 Chains & Basic Rules
            "-P INPUT ACCEPT", "-P FORWARD ACCEPT", "-P OUTPUT ACCEPT",
            "-F INPUT", "-F FORWARD", "-F OUTPUT", "-X", "-Z",
            "-N ZONE_GLOBAL_INPUT", "-N ZONE_GLOBAL_OUTPUT", "-N ZONE_GLOBAL_FORWARD",
            "-N ZONE_PUBLIC_INPUT", "-N ZONE_PUBLIC_OUTPUT", "-N ZONE_PUBLIC_FORWARD",
            "-N ZONE_PRIVATE_LAN_INPUT", "-N ZONE_PRIVATE_LAN_OUTPUT", "-N ZONE_PRIVATE_LAN_FORWARD",
            "-N ZONE_GUEST_WIFI_INPUT", "-N ZONE_GUEST_WIFI_OUTPUT", "-N ZONE_GUEST_WIFI_FORWARD",
            "-N ZONE_VPN_USERS_INPUT", "-N ZONE_VPN_USERS_OUTPUT", "-N ZONE_VPN_USERS_FORWARD",
            "-N ZONE_DMZ_IPV6_INPUT", "-N ZONE_DMZ_IPV6_OUTPUT", "-N ZONE_DMZ_IPV6_FORWARD", # Chains created even if only IPv6 def
            "-A INPUT -j ZONE_GLOBAL_INPUT",
            "-A OUTPUT -j ZONE_GLOBAL_OUTPUT",
            "-A FORWARD -j ZONE_GLOBAL_FORWARD",
            # Zone jumps (order might matter if interfaces overlap, but here they are distinct or specific)
            "-A INPUT -i eth1 -s 192.168.1.0/24 -j ZONE_PRIVATE_LAN_INPUT",
            "-A OUTPUT -o eth1 -d 192.168.1.0/24 -j ZONE_PRIVATE_LAN_OUTPUT",
            "-A FORWARD -i eth1 -s 192.168.1.0/24 -j ZONE_PRIVATE_LAN_FORWARD",
            "-A INPUT -i eth1 -s 192.168.2.0/24 -j ZONE_GUEST_WIFI_INPUT",
            "-A OUTPUT -o eth1 -d 192.168.2.0/24 -j ZONE_GUEST_WIFI_OUTPUT",
            "-A FORWARD -i eth1 -s 192.168.2.0/24 -j ZONE_GUEST_WIFI_FORWARD",
            # eth2 is for dmz_ipv6, so no IPv4 jump for it.
            "-A INPUT -i eth0 -j ZONE_PUBLIC_INPUT",
            "-A OUTPUT -o eth0 -j ZONE_PUBLIC_OUTPUT",
            "-A FORWARD -i eth0 -j ZONE_PUBLIC_FORWARD",
            "-A INPUT -i tun0 -j ZONE_VPN_USERS_INPUT",
            "-A OUTPUT -o tun0 -j ZONE_VPN_USERS_OUTPUT",
            "-A FORWARD -i tun0 -j ZONE_VPN_USERS_FORWARD",
            # Global rules
            "-A ZONE_GLOBAL_INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "-A ZONE_GLOBAL_OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "-A ZONE_GLOBAL_FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "-A ZONE_GLOBAL_INPUT -i lo -j ACCEPT", "-A ZONE_GLOBAL_OUTPUT -o lo -j ACCEPT",
            "-A ZONE_GLOBAL_INPUT -m state --state INVALID -j DROP",
            "-A ZONE_GLOBAL_FORWARD -m state --state INVALID -j DROP",
            "-A ZONE_GLOBAL_INPUT -p icmp --icmp-type echo-request -j ACCEPT",
            # Return from each zone
            "-A ZONE_GLOBAL_INPUT -j RETURN", "-A ZONE_GLOBAL_OUTPUT -j RETURN", "-A ZONE_GLOBAL_FORWARD -j RETURN",
            "-A ZONE_PUBLIC_INPUT -j RETURN", "-A ZONE_PUBLIC_OUTPUT -j RETURN", "-A ZONE_PUBLIC_FORWARD -j RETURN",
            "-A ZONE_PRIVATE_LAN_INPUT -j RETURN", "-A ZONE_PRIVATE_LAN_OUTPUT -j RETURN", "-A ZONE_PRIVATE_LAN_FORWARD -j RETURN",
            "-A ZONE_GUEST_WIFI_INPUT -j RETURN", "-A ZONE_GUEST_WIFI_OUTPUT -j RETURN", "-A ZONE_GUEST_WIFI_FORWARD -j RETURN",
            "-A ZONE_VPN_USERS_INPUT -j RETURN", "-A ZONE_VPN_USERS_OUTPUT -j RETURN", "-A ZONE_VPN_USERS_FORWARD -j RETURN",
            "-A ZONE_DMZ_IPV6_INPUT -j RETURN", "-A ZONE_DMZ_IPV6_OUTPUT -j RETURN", "-A ZONE_DMZ_IPV6_FORWARD -j RETURN",
            # Final policy
            "-P INPUT DROP", "-P FORWARD DROP", "-P OUTPUT ACCEPT", # discard becomes drop

            # IPv6 Chains & Basic Rules
            "ip6tables -P INPUT ACCEPT", "ip6tables -P FORWARD ACCEPT", "ip6tables -P OUTPUT ACCEPT",
            "ip6tables -F INPUT", "ip6tables -F FORWARD", "ip6tables -F OUTPUT", "ip6tables -X", "ip6tables -Z",
            "ip6tables -N ZONE_GLOBAL_INPUT", "ip6tables -N ZONE_GLOBAL_OUTPUT", "ip6tables -N ZONE_GLOBAL_FORWARD",
            "ip6tables -N ZONE_PUBLIC_INPUT", "ip6tables -N ZONE_PUBLIC_OUTPUT", "ip6tables -N ZONE_PUBLIC_FORWARD",
            "ip6tables -N ZONE_PRIVATE_LAN_INPUT", "ip6tables -N ZONE_PRIVATE_LAN_OUTPUT", "ip6tables -N ZONE_PRIVATE_LAN_FORWARD",
            "ip6tables -N ZONE_GUEST_WIFI_INPUT", "ip6tables -N ZONE_GUEST_WIFI_OUTPUT", "ip6tables -N ZONE_GUEST_WIFI_FORWARD",
            "ip6tables -N ZONE_VPN_USERS_INPUT", "ip6tables -N ZONE_VPN_USERS_OUTPUT", "ip6tables -N ZONE_VPN_USERS_FORWARD",
            "ip6tables -N ZONE_DMZ_IPV6_INPUT", "ip6tables -N ZONE_DMZ_IPV6_OUTPUT", "ip6tables -N ZONE_DMZ_IPV6_FORWARD",
            "ip6tables -A INPUT -j ZONE_GLOBAL_INPUT",
            "ip6tables -A OUTPUT -j ZONE_GLOBAL_OUTPUT",
            "ip6tables -A FORWARD -j ZONE_GLOBAL_FORWARD",
            # private_lan and guest_wifi have no IPv6 component
            "ip6tables -A INPUT -i eth2 -s 2001:db8:dmz::/64 -j ZONE_DMZ_IPV6_INPUT",
            "ip6tables -A OUTPUT -o eth2 -d 2001:db8:dmz::/64 -j ZONE_DMZ_IPV6_OUTPUT",
            "ip6tables -A FORWARD -i eth2 -s 2001:db8:dmz::/64 -j ZONE_DMZ_IPV6_FORWARD",
            "ip6tables -A INPUT -i eth0 -j ZONE_PUBLIC_INPUT",
            "ip6tables -A OUTPUT -o eth0 -j ZONE_PUBLIC_OUTPUT",
            "ip6tables -A FORWARD -i eth0 -j ZONE_PUBLIC_FORWARD",
            "ip6tables -A INPUT -i tun0 -j ZONE_VPN_USERS_INPUT",
            "ip6tables -A OUTPUT -o tun0 -j ZONE_VPN_USERS_OUTPUT",
            "ip6tables -A FORWARD -i tun0 -j ZONE_VPN_USERS_FORWARD",
            "ip6tables -A ZONE_GLOBAL_INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "ip6tables -A ZONE_GLOBAL_OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "ip6tables -A ZONE_GLOBAL_FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT",
            "ip6tables -A ZONE_GLOBAL_INPUT -i lo -j ACCEPT", "ip6tables -A ZONE_GLOBAL_OUTPUT -o lo -j ACCEPT",
            "ip6tables -A ZONE_GLOBAL_INPUT -m state --state INVALID -j DROP",
            "ip6tables -A ZONE_GLOBAL_FORWARD -m state --state INVALID -j DROP",
            "ip6tables -A ZONE_GLOBAL_INPUT -p icmpv6 --icmpv6-type echo-request -j ACCEPT",
            "ip6tables -A ZONE_GLOBAL_INPUT -j RETURN", "ip6tables -A ZONE_GLOBAL_OUTPUT -j RETURN", "ip6tables -A ZONE_GLOBAL_FORWARD -j RETURN",
            "ip6tables -A ZONE_PUBLIC_INPUT -j RETURN", "ip6tables -A ZONE_PUBLIC_OUTPUT -j RETURN", "ip6tables -A ZONE_PUBLIC_FORWARD -j RETURN",
            "ip6tables -A ZONE_PRIVATE_LAN_INPUT -j RETURN", "ip6tables -A ZONE_PRIVATE_LAN_OUTPUT -j RETURN", "ip6tables -A ZONE_PRIVATE_LAN_FORWARD -j RETURN",
            "ip6tables -A ZONE_GUEST_WIFI_INPUT -j RETURN", "ip6tables -A ZONE_GUEST_WIFI_OUTPUT -j RETURN", "ip6tables -A ZONE_GUEST_WIFI_FORWARD -j RETURN",
            "ip6tables -A ZONE_VPN_USERS_INPUT -j RETURN", "ip6tables -A ZONE_VPN_USERS_OUTPUT -j RETURN", "ip6tables -A ZONE_VPN_USERS_FORWARD -j RETURN",
            "ip6tables -A ZONE_DMZ_IPV6_INPUT -j RETURN", "ip6tables -A ZONE_DMZ_IPV6_OUTPUT -j RETURN", "ip6tables -A ZONE_DMZ_IPV6_FORWARD -j RETURN",
            "ip6tables -P INPUT DROP", "ip6tables -P FORWARD DROP", "ip6tables -P OUTPUT ACCEPT",
        ]
        actual_commands = self._run_fwsimple_dry_run(config_content, rules_files)
        self.assert_commands_equal(actual_commands, expected_commands)

if __name__ == '__main__':
    unittest.main()
