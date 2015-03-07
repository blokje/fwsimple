from __future__ import unicode_literals, print_function, absolute_import

from fwsimple import lib, constants

import ipaddress

class Zone(lib.FirewallExecution):

    """ A firewall zone will be used for initial packet filtering """


    def __init__(self, firewall, name, expressions):
        """ Define a firewall zone """
        self.expressions = []
        self._firewall = firewall

        self.name = name

        if expressions:
            self.parse_expressions(expressions)

    def parse_expressions(self, expressions):
        for expression in expressions.split(','):
            self.add_expression(expression)


    def add_expression(self, expression):
        subexpression = ZoneExpression(self._firewall, self, expression)
        if self._firewall.has_zone_expression(subexpression):
            raise Warning('Duplicate zone definition detected (zone=%s, expression=%s)' % (self.name, expr))
        else:
            self.expressions.append(subexpression)

    def args_iptables(self):
        creators = []
        for direction in constants.DIRECTION:
            cmd = ['-N', "%s_%s" %
                   (constants.DIRECTION[direction], self.name)]
            creators.append(cmd)
        return creators

    def args_iptables_return(self):
        creators = []
        for direction in constants.DIRECTION:
            cmd = ['-A', "%s_%s" %
                   (constants.DIRECTION[direction], self.name)]
            cmd += ['-j', 'RETURN']
            creators.append(cmd)
        return creators

class ZoneExpression(lib.FirewallExecution):

    """ A subexpression is a small part of the zone definition """

    def __init__(self, firewall, zone, expression):
        self._firewall = firewall
        self._zone = zone
        self.expression = expression

        # Check if expression is specific (specific zones preceed generic
        # zones)
        if self.expression and ':' in self.expression:
            (self.interface, self.source) = self.expression.split(':', 1)
            self.source = ipaddress.ip_network(self.source)
        else:
            self.interface = self.expression
            self.source = None

        self.proto = constants.PROTO_IPV4 + constants.PROTO_IPV6
        if self.source:
            if self.source.version == 4:
                self.proto -= constants.PROTO_IPV6
            elif self.source.version == 6:
                self.proto -= constants.PROTO_IPV4

    def __eq__(self, other):
        return (self.interface == other.interface) and (self.source == other.source)

    def args_iptables(self):
        creators = []
        for direction in constants.DIRECTION:
            cmd = ['-A', constants.IPTABLES_DIRECTION[direction]]
            cmd += [ '-m', 'comment', '--comment', 'Zone %s' % self._zone.name ]

            if self.interface:
                if direction == 'out':
                    cmd += ['-o', self.interface]
                    if self.source:
                        cmd += ['-d', str(self.source)]
                else:
                    cmd += ['-i', self.interface]
                    if self.source:
                        cmd += ['-s', str(self.source)]

            cmd += ['-j', '%s_%s' %
                    (constants.DIRECTION[direction], self._zone.name)]

            creators.append(cmd)
        return creators

    @property
    def specific(self):
        if self.source:
            return True
        return False

