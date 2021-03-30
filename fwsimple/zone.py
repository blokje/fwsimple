from __future__ import unicode_literals, print_function, absolute_import
from typing import List, Optional, TYPE_CHECKING, Union

from fwsimple import lib, constants

import ipaddress
if TYPE_CHECKING:
    from .firewall import Firewall
    from .xtypes import IpNetwork

# Bugs:
# 1. Detection does not work if duplicate expression is made in same zone
class Zone(lib.FirewallExecution):

    """ A firewall zone will be used for initial packet filtering """

    def __init__(self, firewall: "Firewall", name: str, expressions: Optional[str]) -> None:
        """ Define a firewall zone """
        self._firewall = firewall
        self.name = name

        self.expressions: List[ZoneExpression] = []

        if expressions:
            self.parse_expressions(expressions)



    def parse_expressions(self, expressions: str) -> None:
        for expression in expressions.split(","):
            self.add_expression(expression)

    def add_expression(self, expression: Optional[str]) -> None:
        subexpression = ZoneExpression(self._firewall, self, expression)
        if self._firewall.has_zone_expression(subexpression):
            raise Warning(
                "Duplicate zone definition detected (zone=%s, expression=%s)"
                % (self.name, subexpression)
            )
        else:
            self.expressions.append(subexpression)

    def __repr__(self) -> str:
        """ Return representation of object """
        myvars = vars(self)
        myrepr = ", ".join(
            "%s=%s" % (var, myvars[var])
            for var in myvars
            if not var.startswith("_") and myvars[var] is not None
        )

        return "<Zone(%s)>" % myrepr


class ZoneExpression(lib.FirewallExecution):

    """ A subexpression is a small part of the zone definition """
    source: Optional["IpNetwork"]
    interface: Optional[str]
    
    def __init__(self, firewall: "Firewall", zone: "Zone", expression: Optional[str]) -> None:
        self._firewall = firewall
        self._zone = zone
        self.expression = expression

        # Check if expression is specific (specific zones preceed generic
        # zones)
        if self.expression and ":" in self.expression:
            (self.interface, source_network) = self.expression.split(":", 1)
            self.source = ipaddress.ip_network(source_network)
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
    def specific(self) -> bool:
        """ Property determing if the expression is specific or generic """
        return self.source is not None

    def __repr__(self) -> str:
        """ Return representation of object """
        myvars = vars(self)
        myrepr = ", ".join(
            "%s=%s" % (var, myvars[var])
            for var in myvars
            if not var.startswith("_") and myvars[var] is not None
        )

        return "<ZoneExpression(%s)>" % myrepr

    # Sorting
    def __eq__(self, other: object) -> bool:
        if isinstance(other, ZoneExpression):
            return (self.interface == other.interface) and (self.source == other.source)
        return False

    def __ne__(self, other: object) -> bool:
        if isinstance(other, ZoneExpression):
            return (self.interface != other.interface) or (self.source != other.source)
        return False

    def __lt__(self, other: object) -> bool:
        """ Check if I should be smaller than the other """
        if not isinstance(other, ZoneExpression):
            return False
            
        if self._zone.name == constants.GLOBAL_ZONE_NAME:
            return True
        elif other._zone.name == constants.GLOBAL_ZONE_NAME:
            return False
        elif self.source and other.source:
            ### Check if the other has more addresses than I do
            return self.source.num_addresses < other.source.num_addresses
        elif self.source:
            ### Other has no definition, so we are smaller!
            return True
        return False

    # def __le__(self, other) -> bool:
    #     """ Check if lesser than OR equal """
    #     return self.__eq__(other) or self.__lt__(other)

    # def __gt__(self, other) -> bool:
    #     """ Check if I should be greater than the other """
    #     if self._zone.name == constants.GLOBAL_ZONE_NAME:
    #         return False
    #     if other._zone.name == constants.GLOBAL_ZONE_NAME:
    #         return True
    #     elif self.source and other.source:
    #         return self.source.num_addresses > other.source.num_addresses
    #     elif self.source:
    #         return False
    #     return True

    # def __ge__(self, other) -> bool:
    #     """ Check if greater than OR equal """
    #     return self.__eq__(other) or self.__gt__(other)
