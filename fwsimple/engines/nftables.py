from __future__ import unicode_literals, print_function, absolute_import
from typing import Iterable, List, TYPE_CHECKING
import warnings

from fwsimple import constants
from fwsimple.engines import BaseEngine

if TYPE_CHECKING:
    from ..zone import Zone, ZoneExpression
    from ..rules import Filter
    from ..xtypes import TrafficDirection, FilterAction

# Define actions for nftables
NFTABLES_ACTIONS = {"accept": "accept", "reject": "reject", "discard": "drop"}


class Engine(BaseEngine):
    """Nftables Engine"""

    NFTABLES_BASE_CHAINS = {"in": "input", "out": "output", "forward": "forward"}

    @staticmethod
    def _translate_nft_port_set(ports: List[str], multiport: bool) -> str:
        """Translate port list/range to nftables compatible format."""
        if not ports:
            return ""

        if len(ports) == 1 and not multiport and '-' not in ports[0]:
            return ports[0]

        return "{ %s }" % ", ".join(ports)

    def init(self) -> Iterable[List[str]]:
        """Initialize the firewall, flush existing and add
        default tables and chains"""
        self._nft = ["nft"]

        # Flush existing ruleset
        yield self._nft + ["flush", "ruleset"]

        # Create inet table for fwsimple
        yield self._nft + ["add", "table", "inet", "fwsimple"]

        # Create base chains for inet table
        # Default policy is accept, can be changed later by set_default_policy
        base_chains = {
            "input": "{ type filter hook input priority 0 ; policy accept ; }",
            "forward": "{ type filter hook forward priority 0 ; policy accept ; }",
            "output": "{ type filter hook output priority 0 ; policy accept ; }",
        }

        for chain_name, chain_config in base_chains.items():
            yield self._nft + ["add", "chain", "inet", "fwsimple", chain_name, chain_config]

        # Add loopback rules
        yield self._nft + ["add", "rule", "inet", "fwsimple", "input", "iif", "lo", "accept", "comment", "\"Allow all loopback input\""]
        yield self._nft + ["add", "rule", "inet", "fwsimple", "output", "oif", "lo", "accept", "comment", "\"Allow all loopback output\""]

        # Add basic conntrack rules for established/related and invalid states
        yield self._nft + ["add", "rule", "inet", "fwsimple", "input", "ct", "state", "related,established", "accept"]
        yield self._nft + ["add", "rule", "inet", "fwsimple", "output", "ct", "state", "related,established", "accept"]
        yield self._nft + ["add", "rule", "inet", "fwsimple", "forward", "ct", "state", "related,established", "accept"]

        yield self._nft + ["add", "rule", "inet", "fwsimple", "input", "ct", "state", "invalid", "drop"]
        yield self._nft + ["add", "rule", "inet", "fwsimple", "forward", "ct", "state", "invalid", "drop"]

        # IPv4 ICMP sane defaults
        ipv4_icmp_rules = [
            (["ip", "version", "4", "icmp", "type", "echo-request", "accept"], "\"[ICMP] Echo Request\""),
            (["ip", "version", "4", "icmp", "type", "destination-unreachable", "code", "4", "accept"], "\"[ICMP] Fragmentation needed\""),
            (["ip", "version", "4", "icmp", "type", "destination-unreachable", "code", "3", "accept"], "\"[ICMP] Port unreachable\""),
            (["ip", "version", "4", "icmp", "type", "destination-unreachable", "code", "1", "accept"], "\"[ICMP] Host unreachable\""),
            (["ip", "version", "4", "icmp", "type", "source-quench", "accept"], "\"[ICMP] Source Quench (RFC 792)\""),
        ]
        for rule_parts, comment in ipv4_icmp_rules:
            yield self._nft + ["add", "rule", "inet", "fwsimple", "input"] + rule_parts + ["comment", comment]

        # IPv6 ICMP and other sane defaults
        ipv6_rules = [
            (["ip", "version", "6", "meta", "l4proto", "ipv6-nonxt", "accept"], "\"[IPv6] No next header RFC2460\""),
            (["ip", "version", "6", "icmpv6", "type", "packet-too-big", "accept"], "\"[ICMPv6] Packet too big\""),
            (["ip", "version", "6", "icmpv6", "type", "time-exceeded", "accept"], "\"[ICMPv6] Time exceeded\""),
            (["ip", "version", "6", "icmpv6", "type", "133", "accept"], "\"[ICMPv6] Router sollicitation\""),
            (["ip", "version", "6", "icmpv6", "type", "134", "accept"], "\"[ICMPv6] Router advertisement\""),
            (["ip", "version", "6", "icmpv6", "type", "135", "accept"], "\"[ICMPv6] Neighbor sollicitation\""),
            (["ip", "version", "6", "icmpv6", "type", "136", "accept"], "\"[ICMPv6] Neighbor advertisement\""),
            (["ip", "version", "6", "icmpv6", "type", "echo-request", "accept"], "\"[ICMPv6] Echo Request\""),
        ]
        for rule_parts, comment in ipv6_rules:
            yield self._nft + ["add", "rule", "inet", "fwsimple", "input"] + rule_parts + ["comment", comment]

    def zone_create(self, zone: "Zone") -> Iterable[List[str]]:
        """Create the zone chains"""
        for direction_key in constants.DIRECTION:
            chain_name = f"ZONE_{constants.DIRECTION[direction_key]}_{zone.name}"
            yield self._nft + ["add", "chain", "inet", "fwsimple", chain_name]

    def zone_expression_create(
        self, expression: "ZoneExpression"
    ) -> Iterable[List[str]]:
        """Create expressions to jump to zone chains for all directions."""

        base_chain_map = {
            "in": "input",
            "out": "output",
            "forward": "forward"
        }

        for direction_key in constants.DIRECTION.keys(): # "in", "out", "forward"
            base_chain_name = base_chain_map.get(direction_key)
            if not base_chain_name:
                continue

            target_zone_chain_name = f"ZONE_{constants.DIRECTION[direction_key]}_{expression._zone.name}"

            cmd = self._nft + ["add", "rule", "inet", "fwsimple", base_chain_name]

            # Add match criteria first
            if expression.interface:
                if direction_key == "out":
                    cmd += ["oif", expression.interface]
                    if expression.source:
                        cmd += ["ip", "daddr", str(expression.source)]
                else:  # 'in' or 'forward'
                    cmd += ["iif", expression.interface]
                    if expression.source:
                        cmd += ["ip", "saddr", str(expression.source)]
            elif expression.source:
                if direction_key == "out":
                    cmd += ["ip", "daddr", str(expression.source)]
                else:
                    cmd += ["ip", "saddr", str(expression.source)]

            # Then add comment
            cmd += ["comment", f"Zone {expression._zone.name}"]

            # Finally, add verdict (jump)
            cmd += ["jump", target_zone_chain_name]
            yield cmd

    def zone_close(self, zone: "Zone") -> Iterable[List[str]]:
        """Add a return rule to the end of zone chains"""
        for direction_key in constants.DIRECTION:
            chain_name = f"ZONE_{constants.DIRECTION[direction_key]}_{zone.name}"
            yield self._nft + ["add", "rule", "inet", "fwsimple", chain_name, "return"]

    def rule_create(self, rule: "Filter") -> Iterable[List[str]]:
        """Create firewall rules"""
        chain_name = f"ZONE_{constants.DIRECTION[rule.direction]}_{rule.zone}"

        if rule.country:
            warnings.warn(
                f"GeoIP filtering for rule '{rule.name}' (country: {rule.country}) "
                "is not yet implemented in the nftables engine. "
                "The rule will be created without GeoIP matching."
            )

        for source, destination in rule.get_source_destinations():
            cmd_parts = []

            if rule.protocol:
                cmd_parts.append(rule.protocol)
                if rule.protocol in ["tcp", "udp"] and rule.port:
                    translated_ports = self._translate_nft_port_set(rule.port, rule.multiport)
                    if translated_ports:
                        cmd_parts.extend(["dport", translated_ports])

            if source:
                if hasattr(source, 'version') and source.version == 6:
                    cmd_parts.extend(["ip6", "saddr", str(source)])
                else: # IPv4 or unversioned (should be caught by validation earlier)
                    cmd_parts.extend(["ip", "saddr", str(source)])
            if destination:
                if hasattr(destination, 'version') and destination.version == 6:
                    cmd_parts.extend(["ip6", "daddr", str(destination)])
                else: # IPv4 or unversioned
                    cmd_parts.extend(["ip", "daddr", str(destination)])

            action_cmd = self._nft + ["add", "rule", "inet", "fwsimple", chain_name]
            action_cmd += ["ct", "state", "new"]
            action_cmd.extend(cmd_parts) # Add protocol, port, IPs first
            action_cmd += ["comment", rule.name] # Then comment

            if rule.log:
                action_cmd.extend(["log", "prefix", f"{rule.name[:24]}: "])

            action_cmd.append(NFTABLES_ACTIONS[rule.action])

            yield action_cmd

    def set_default_policy(
        self, direction: "TrafficDirection", policy: "FilterAction"
    ) -> Iterable[List[str]]:
        """Set default firewall policy for a base chain."""
        nft_chain_name = self.NFTABLES_BASE_CHAINS.get(direction)
        if not nft_chain_name:
            # This should not happen with valid TrafficDirection
            return

        nft_policy_action = NFTABLES_ACTIONS.get(policy)
        if not nft_policy_action:
            # This should not happen with valid FilterAction
            return

        if nft_policy_action == "reject":
            nft_policy_action = "drop"
            warnings.warn(
                f"Nftables backend: Default policy 'reject' for base chain '{nft_chain_name}' "
                "is implemented as 'drop'. Use specific rules for 'reject' actions.",
                UserWarning,
            )

        chain_definition = (
            f"{{ type filter hook {nft_chain_name} priority 0 ; policy {nft_policy_action} ; }}"
        )

        cmd = self._nft + [
            "add", "chain", "inet", "fwsimple", nft_chain_name, chain_definition
        ]
        yield cmd
