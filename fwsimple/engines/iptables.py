""" IPTables Engine """
from __future__ import unicode_literals, print_function, absolute_import

from fwsimple import constants
from fwsimple.engines import BaseEngine


class Engine(BaseEngine):
    """ Iptables Engine """

    def init(self):
        """ Initialize the firewall, flush existing and add
            default rules defined in constants """
        # Default configurations
        for _ in constants.BASIC_IPTABLES_INIT:
            yield ['iptables'] + _
            yield ['ip6tables'] + _
        for _ in constants.BASIC_IP4TABLES_INIT:
            yield ['iptables'] + _
        for _ in constants.BASIC_IP6TABLES_INIT:
            yield ['ip6tables'] + _
    #
    # Zones
    #
    def zone_create(self, zone):
        """ Create the zones for iptable and ip6tables """
        for direction in constants.DIRECTION:
            cmd = ['-N', "%s_%s" % (constants.DIRECTION[direction], zone.name)]
            yield [ 'iptables' ] + cmd
            yield [ 'ip6tables' ] + cmd

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

            if expression.proto & constants.PROTO_IPV4:
                yield ['iptables'] + cmd
            if expression.proto & constants.PROTO_IPV6:
                yield ['ip6tables'] + cmd
