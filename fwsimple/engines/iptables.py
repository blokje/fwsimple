""" IPTables Engine """
from __future__ import unicode_literals, print_function, absolute_import
from typing import Iterable, List, TYPE_CHECKING

from fwsimple import constants
from fwsimple.engines import BaseEngine

if TYPE_CHECKING:
    from ..zone import Zone, ZoneExpression
    from ..rules import Filter
    from ..xtypes import TrafficDirection, FilterAction

class Engine(BaseEngine):
    """ Iptables Engine """

    def init(self) -> Iterable[List[str]]:
        """Initialize the firewall, flush existing and add
        default rules defined in constants"""

        self._iptables = ["iptables"]
        self._ip6tables = ["ip6tables"]

        if self._iptables_supports_lockx:
            self._iptables += ["-w"]
            self._ip6tables += ["-w"]

        # Default configurations
        for _ in constants.BASIC_IPTABLES_INIT:
            yield self._iptables + _
            yield self._ip6tables + _
        for _ in constants.BASIC_IP4TABLES_INIT:
            yield self._iptables + _
        for _ in constants.BASIC_IP6TABLES_INIT:
            yield self._ip6tables + _

    @property
    def _iptables_supports_lockx(self) -> bool:
        return self.do_exec(["iptables", "-w", "-L", "-n"], False) == 0

    #
    # Zones
    #
    def zone_create(self, zone: "Zone") -> Iterable[List[str]]:
        """ Create the zones for iptable and ip6tables """
        for direction in constants.DIRECTION:
            cmd = ["-N", "%s_%s" % (constants.DIRECTION[direction], zone.name)]
            yield from self.__iptables(cmd)

    def zone_expression_create(self, expression: "ZoneExpression") -> Iterable[List[str]]:
        """ Create expressions for the zones based on interface and optional source """
        for direction in constants.DIRECTION:
            cmd = ["-A", constants.IPTABLES_DIRECTION[direction]]
            cmd += ["-m", "comment", "--comment", "Zone %s" % expression._zone.name]

            if expression.interface:
                if direction == "out":
                    cmd += ["-o", expression.interface]
                    if expression.source:
                        cmd += ["-d", str(expression.source)]
                else:
                    cmd += ["-i", expression.interface]
                    if expression.source:
                        cmd += ["-s", str(expression.source)]

            cmd += [
                "-j",
                "%s_%s" % (constants.DIRECTION[direction], expression._zone.name),
            ]

            yield from self.__iptables(cmd, expression.proto)

    def zone_close(self, zone: "Zone") -> Iterable[List[str]]:
        """ Finish up the zones in iptables and ip6tables """
        for direction in constants.DIRECTION:
            cmd = ["-A", "%s_%s" % (constants.DIRECTION[direction], zone.name)]
            cmd += ["-j", "RETURN"]
            yield from self.__iptables(cmd)

    #
    # Rules
    #
    def rule_create(self, rule: "Filter") -> Iterable[List[str]]:
        policy = ["-A", "%s_%s" % (constants.DIRECTION[rule.direction], rule.zone)]
        policy += ["-m", "conntrack", "--ctstate", "NEW"]
        policy += ["-m", "comment", "--comment", rule.name]

        if rule.protocol:
            policy += ["-p", rule.protocol]

            if rule.port:
                if rule.multiport:
                    policy += ["-m", "multiport"]
                policy += ["--dport", self._translate_port_range(rule.port)]

        if rule.country:
            policy += ["-m", "geoip"]
            if rule.direction == "in":
                policy += ["--src-cc", rule.country]
            else:
                policy += ["--dst-cc", rule.country]

        for (source, destination) in rule.get_source_destinations():
            cmd = list(policy)
            proto = constants.PROTO_IPV4 + constants.PROTO_IPV6

            if source:
                cmd += ["-s", str(source)]
                if source.version == 4:
                    proto = proto & constants.PROTO_IPV4
                else:
                    proto = proto & constants.PROTO_IPV6

            if destination:
                cmd += ["-d", str(destination)]
                if destination.version == 4:
                    proto = proto & constants.PROTO_IPV4
                else:
                    proto = proto & constants.PROTO_IPV6

            if rule.log:
                logcmd = cmd + ["-j", "LOG", "--log-prefix", "%s " % rule.name[0:28]]
                yield from self.__iptables(logcmd, proto)

            cmd += ["-j", constants.IPTABLES_ACTIONS[rule.action]]
            yield from self.__iptables(cmd, proto)

    def set_default_policy(self, direction: "TrafficDirection", policy: "FilterAction") -> Iterable[List[str]]:
        """ Set default firewall policy """
        chain = constants.IPTABLES_DIRECTION[direction]
        action = constants.IPTABLES_ACTIONS[policy]
        cmd = ["-A", chain, "-j", action]
        yield from self.__iptables(cmd)

    def __iptables(self, cmd: List[str], protoversion: int =constants.PROTO_IPV4 + constants.PROTO_IPV6) -> Iterable[List[str]]:
        if protoversion & constants.PROTO_IPV4:
            yield self._iptables + cmd
        if protoversion & constants.PROTO_IPV6:
            yield self._ip6tables + cmd

    def _translate_port_range(self, ports: List[str]) -> str:
        """ Translate port range to IPtables compatible format """
        _ports = []
        for port in ports:
            if "-" in port:
                (start, end) = port.split("-")
                _ports.append("%d:%d" % (int(start), int(end)))
            else:
                _ports.append("%d" % int(port))
        return ",".join(_ports)
