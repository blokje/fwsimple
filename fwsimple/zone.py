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

    """A firewall zone will be used for initial packet filtering"""

    def __init__(
        self, firewall: "Firewall", name: str, expressions: Optional[str]
    ) -> None:
        """Define a firewall zone"""
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
        self.expressions.append(subexpression)

    def __repr__(self) -> str:
        """Return representation of object"""
        myvars = vars(self)
        myrepr = ", ".join(
            "%s=%s" % (var, myvars[var])
            for var in myvars
            if not var.startswith("_") and myvars[var] is not None
        )

        return "<Zone(%s)>" % myrepr


class ZoneExpression(lib.FirewallExecution):

    """A subexpression is a small part of the zone definition"""

    source: Optional["IpNetwork"]
    interface: Optional[str]

    def __init__(
        self, firewall: "Firewall", zone: "Zone", expression: Optional[str]
    ) -> None:
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
        """Property determing if the expression is specific or generic"""
        return self.source is not None

    def __repr__(self) -> str:
        """Return representation of object"""
        myvars = vars(self)
        myrepr = ", ".join(
            "%s=%s" % (var, myvars[var])
            for var in myvars
            if not var.startswith("_") and myvars[var] is not None
        )

        return "<ZoneExpression(%s)>" % myrepr

    # Sorting methods: __eq__, __ne__, and __lt__ are implemented to allow
    # ZoneExpression objects to be sorted. This is crucial for ensuring
    # a deterministic order when generating firewall rules, contributing to
    # predictable firewall behavior. __lt__ defines the primary sorting logic.
    def __eq__(self, other: object) -> bool:
        if isinstance(other, ZoneExpression):
            return (self.interface == other.interface) and (self.source == other.source)
        return False

    def __ne__(self, other: object) -> bool:
        if isinstance(other, ZoneExpression):
            return (self.interface != other.interface) or (self.source != other.source)
        return False

    # The __lt__ method implements a multi-level sorting logic to ensure a
    # deterministic total order for ZoneExpression objects. This is essential for
    # generating firewall rules in a consistent sequence, which helps in debugging
    # and maintaining predictable firewall behavior.
    # The sorting criteria are applied in the following order of precedence:
    # 1. Global Status: Global zones are considered "less than" non-global zones.
    # 2. Source Presence: Expressions with a source are "less than" those without
    #    (maintaining original fwsimple behavior for this primary key).
    # 3. Source Network Size: If both have sources, the one with fewer IP addresses
    #    is "less than".
    # 4. Interface Name (Secondary Sort):
    #    - None interfaces come before actual interface names.
    #    - Interface names are compared lexicographically.
    # 5. String Representation of Source (Tertiary Sort): If all previous criteria
    #    are equal (e.g., both have sources with the same network size, and identical
    #    interfaces), their string representations (e.g., "1.2.3.0/24") are compared
    #    lexicographically.
    # This comprehensive comparison aims to ensure that for any two distinct
    # ZoneExpression objects `a` and `b`, exactly one of `a < b` or `b < a` is
    # true, unless they are deemed equal by all criteria (in which case `a < b`
    # and `b < a` are both false).
    def __lt__(self, other: object) -> bool:
        """Check if I should be smaller than the other for deterministic sorting."""
        if not isinstance(other, ZoneExpression):
            return NotImplemented

        # Criterion 1: Global vs Non-Global
        # Global zones come before non-global zones.
        is_self_global = self._zone.name == constants.GLOBAL_ZONE_NAME
        is_other_global = other._zone.name == constants.GLOBAL_ZONE_NAME

        if is_self_global != is_other_global:
            return is_self_global  # True if self is global and other is not, False otherwise.

        # At this point, either both are global or both are non-global.
        # They are "equal" based on global status.

        # Criterion 2: Source presence (maintaining original logic: "source" < "no source")
        # This means an expression with a source is considered "smaller" than one without.
        if self.source and not other.source:
            return True
        if not self.source and other.source:
            return False

        # At this point, either both have sources or both lack sources.
        # They are "equal" based on source presence.

        # Criterion 3: Network size (if both have sources)
        # Smaller number of addresses comes before larger.
        if self.source and other.source:
            # This check implies self.source and other.source are not None
            if self.source.num_addresses != other.source.num_addresses:
                return self.source.num_addresses < other.source.num_addresses

        # At this point, if both had sources, their num_addresses are the same.
        # Or, both lack sources.
        # They are "equal" based on network size.

        # Criterion 4: Interface comparison (Secondary sort)
        # None interface comes before string interface.
        # Lexicographical for string interfaces.
        if self.interface is None and other.interface is not None:
            return True
        if self.interface is not None and other.interface is None:
            return False

        if self.interface is not None and other.interface is not None:
            if self.interface != other.interface:
                return self.interface < other.interface

        # At this point, interfaces are "equal" (both None or same string).

        # Criterion 5: Source string representation (Tertiary sort)
        # This applies if both have sources (and same num_addresses, same interface)
        # or if both lack sources (and same interface).
        # str(None) is "None", so this handles None sources consistently if we were to use it.
        # However, source presence is primary. This is for disambiguating otherwise-equal sources.

        if self.source and other.source:
            # Both sources are present, num_addresses are same, interfaces are same.
            # Compare their string representations.
            s_str_self = str(self.source)
            s_str_other = str(other.source)
            if s_str_self != s_str_other:
                return s_str_self < s_str_other
        # If one source is None and the other isn't, primary criterion 2 handled it.
        # If both sources are None, they are equal by this criterion.

        # If all criteria are equal, then self is not strictly less than other.
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
