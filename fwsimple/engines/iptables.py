""" IPTables Engine """
from __future__ import unicode_literals, print_function, absolute_import

from fwsimple import constants
from fwsimple.engines import BaseEngine


class Engine(BaseEngine):
    """ Iptables Engine """

    def init(self):
        """ Initialize the firewall, flush existing and add
            default rules defined in constants """

        self._iptables = [ 'iptables' ]
        self._ip6tables = [ 'ip6tables' ]


        if self._iptables_supports_lockx:
            self._iptables += [ '-w' ]
            self._ip6tables += [ '-w' ]

        # Default configurations
        for _ in constants.BASIC_IPTABLES_INIT:
            yield self._iptables + _
            yield self._ip6tables + _
        for _ in constants.BASIC_IP4TABLES_INIT:
            yield self._iptables + _
        for _ in constants.BASIC_IP6TABLES_INIT:
            yield self._ip6tables + _

    @property
    def _iptables_supports_lockx(self):
        if self.do_exec(['iptables', '-w', '-L', '-n'], False) == 0:
            return True
        else:
            return False

    #
    # Zones
    #
    def zone_create(self, zone):
        """ Create the zones for iptable and ip6tables """
        for direction in constants.DIRECTION:
            cmd = ['-N', "%s_%s" % (constants.DIRECTION[direction], zone.name)]
            for _cmd in self.__iptables(cmd):
                yield _cmd

    def zone_expression_create(self, expression):
        """ Create expressions for the zones based on interface and optional source """
        for direction in constants.DIRECTION:
            cmd = ['-A', constants.IPTABLES_DIRECTION[direction]]
            cmd += [ '-m', 'comment', '--comment', 'Zone %s' % expression._zone.name ]

            if expression.interface:
                if direction == 'out':
                    cmd += ['-o', expression.interface]
                    if expression.source:
                        cmd += ['-d', str(expression.source)]
                else:
                    cmd += ['-i', expression.interface]
                    if expression.source:
                        cmd += ['-s', str(expression.source)]

            cmd += ['-j', '%s_%s' %
                    (constants.DIRECTION[direction], expression._zone.name)]
            
            for _cmd in self.__iptables(cmd, expression.proto):
                yield _cmd

    def zone_close(self, zone):
        """ Finish up the zones in iptables and ip6tables """
        for direction in constants.DIRECTION:
            cmd = ['-A', "%s_%s" % (constants.DIRECTION[direction], zone.name)]
            cmd += ['-j', 'RETURN']
            for _cmd in self.__iptables(cmd):
                yield _cmd

    #
    # Rules
    #
    def rule_create(self, rule):
        policy = [ '-A', '%s_%s' % (constants.DIRECTION[rule.direction], rule.zone)]
        policy += ['-m', 'conntrack', '--ctstate', 'NEW']
        policy += ['-m', 'comment', '--comment', rule.name]

        if rule.protocol:
            policy += ['-p', rule.protocol]

            if rule.port:
                if rule.multiport:
                    policy += ['-m', 'multiport']
                policy += [ '--dport', self._translate_port_range(rule.port) ]

        if rule.country:
            policy += [ '-m', 'geoip' ]
            if rule.direction == "in":
                policy += ['--src-cc', rule.country]
            else:
                policy += ['--dst-cc', rule.country]

        for (source, destination) in rule.get_source_destinations():
            cmd = list(policy)
            proto = constants.PROTO_IPV4 + constants.PROTO_IPV6

            if source:
                cmd += [ '-s', str(source) ]
                if source.version == 4:
                    proto = proto & constants.PROTO_IPV4
                else:
                    proto = proto & constants.PROTO_IPV6

            if destination:
                cmd += [ '-d', str(destination) ]
                if destination.version == 4:
                    proto = proto & constants.PROTO_IPV4
                else:
                    proto = proto & constants.PROTO_IPV6

            if rule.log:
                logcmd = cmd + ['-j', 'LOG', '--log-prefix', '%s ' % rule.name[0:28]]
                for _cmd in self.__iptables(logcmd, proto):
                    yield _cmd

            cmd += ['-j', constants.IPTABLES_ACTIONS[rule.action]] 
            for _cmd in self.__iptables(cmd, proto):
                yield _cmd

    def set_default_policy(self, direction, policy):
        """ Set default firewall policy """
        chain = constants.IPTABLES_DIRECTION[direction]
        action = constants.IPTABLES_ACTIONS[policy]
        cmd = ['-A', chain, '-j', action]
        for _cmd in self.__iptables(cmd):
            yield _cmd

    def __iptables(self, cmd, protoversion = constants.PROTO_IPV4 + constants.PROTO_IPV6):
        if protoversion & constants.PROTO_IPV4:
            yield self._iptables + cmd
        if protoversion & constants.PROTO_IPV6:
            yield self._ip6tables + cmd

    def _translate_port_range(self, ports):
        """ Translate port range to IPtables compatible format """
        _ports = []
        for port in ports:
            if '-' in port:
                (start, end) = port.split('-')
                _ports.append('%d:%d' % (int(start), int(end)))
            else:
                _ports.append('%d' % int(port))
        return ','.join(_ports)
