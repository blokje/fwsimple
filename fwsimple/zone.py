from __future__ import unicode_literals, print_function, absolute_import

from fwsimple import lib, constants

import ipaddress

# Bugs:
# 1. Detection does not work if duplicate expression is made in same zone
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
            raise Warning('Duplicate zone definition detected (zone=%s, expression=%s)' % (self.name, subexpression))
        else:
            self.expressions.append(subexpression)

    def __repr__(self):
        """ Return representation of object """
        myvars = vars(self)
        myrepr = ", ".join(["%s=%s" % (var, myvars[var]) for var in myvars if not var.startswith('_') and myvars[var] is not None])
        return '<Zone(%s)>' % myrepr

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

    @property
    def specific(self):
        """ Property determing if the expression is specific or generic """
        if self.source:
            return True
        return False

    def __repr__(self):
        """ Return representation of object """
        myvars = vars(self)
        myrepr = ", ".join(["%s=%s" % (var, myvars[var]) for var in myvars if not var.startswith('_') and myvars[var] is not None])
        return '<ZoneExpression(%s)>' % myrepr

    # Sorting
    def __eq__(self, other):
        return (self.interface == other.interface) and (self.source == other.source)

    def __ne__(self, other):
        return (self.interface != other.interface) or (self.source != other.source)

    def __lt__(self, other):
        """ Check if I should be smaller than the other """
        if self._zone.name == constants.GLOBAL_ZONE_NAME:
            return True
        elif other._zone.name == constants.GLOBAL_ZONE_NAME:
            return False
        elif self.source and other.source:
            ### Check if the other has more addresses than I do
            return self.source.num_addresses < other.source.num_addresses
        elif self.source and not other.source:
            ### Other has no definition, so we are smaller!
            return True
        return False

    def __le__(self, other):
        """ Check if lesser than OR equal """
        return self.__eq__(other) or self.__lt__(other)

    def __gt__(self, other):
        """ Check if I should be greater than the other """
        if self._zone.name == constants.GLOBAL_ZONE_NAME:
            return False
        if other._zone.name == constants.GLOBAL_ZONE_NAME:
            return True
        elif self.source and other.source:
            return self.source.num_addresses > other.source.num_addresses
        elif self.source and not other.source:
            return False
        return True

    def __ge__(self, other):
        """ Check if greater than OR equal """
        return self.__eq__(other) or self.__gt__(other)
