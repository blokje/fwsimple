from __future__ import unicode_literals, print_function, absolute_import
from typing import Iterable, List, Optional, TYPE_CHECKING

# TODO: Rename Rule and Execution
from fwsimple.lib import FirewallRule, FirewallExecution
from fwsimple import constants

import ipaddress

if TYPE_CHECKING:
    from fwsimple.zone import Zone
    from fwsimple.firewall import Firewall
    from fwsimple.xtypes import TrafficDirection, FilterAction, FilterProtocol, IpNetwork, IpSourceDestMapping


class Filter(FirewallRule, FirewallExecution):
    port: Optional[List[str]]
    source: Optional[List[IpNetwork]]
    destination: Optional[List[IpNetwork]]

    def __init__(
        self,
        name: str,
        firewall: "Firewall",
        zone: str,
        source: Optional[str] = None,
        destination: Optional[str] = None,
        port: Optional[str] = None,
        protocol: "FilterProtocol" = "tcp",
        action: "FilterAction" = "accept",
        log: bool = False,
        direction: "TrafficDirection" = "in",
        country: Optional[str] = None,
        # **options
    ):
        """ Define firewall definition """

        # Private
        self._firewall = firewall
        # self._options = options

        # Public : Meta data
        self.name = name

        if self._firewall.has_zone(zone):
            self.zone = zone
        else:
            raise Warning("Zone %s is not defined! (%s)" % (zone, self.name))

        self.set_direction(direction)
        self.set_source(source)
        self.set_destination(destination)
        self.set_port(port)
        self.set_country(country)

        self.protocol = protocol

        # Public : Actions
        if action in constants.IPTABLES_ACTIONS:
            self.action = action
        else:
            raise Exception("Action '%s' is not understood! (%s)" % (action, self.name))

        self.log = bool(log)

    def set_direction(self, direction: "TrafficDirection") -> None:
        """ Set rule direction """
        if direction in constants.DIRECTION:
            self.direction = direction
        else:
            raise Exception(
                "Direction '%s' is not understood! (%s)" % (direction, self.name)
            )

    def set_source(self, source: Optional[str] = None) -> None:
        """ Set source address(es) """
        if source:
            self.source = [
                ipaddress.ip_network(address.strip()) for address in source.split(",")
            ]
        else:
            self.source = None

    def set_destination(self, destination: Optional[str] = None) -> None:
        """ Set destination address(es) """
        if destination:
            self.destination = [
                ipaddress.ip_network(address.strip())
                for address in destination.split(",")
            ]
        else:
            self.destination = None

    def get_source_destinations(self) -> Iterable[IpSourceDestMapping]:
        """ Yields all possible source/destination combinations """
        if self.source and self.destination:
            for source in self.source:
                for destination in self.destination:
                    if isinstance(source, ipaddress.IPv4Network) and isinstance(destination, ipaddress.IPv4Network):
                        yield (source,destination)
                    elif isinstance(source, ipaddress.IPv6Network) and isinstance(destination, ipaddress.IPv6Network):
                        yield (source, destination)

        elif self.source:
            for source in self.source:
                yield (source, None)

        elif self.destination:
            for destination in self.destination:
                yield (None, destination)

        else:
            yield (None, None)

    def set_port(self, port: Optional[str] = None) -> None:
        # Public : Protocol/ports
        self.port = None if not port else port.split(",")

    def set_country(self, country: Optional[str] = None) -> None:
        self.country = None if not country else country

    @property
    def multiport(self) -> bool:
        if self.port:
            return "-" in self.port[0] or len(self.port) != 1
        else:
            return False

    def __repr__(self) -> str:
        myvars = vars(self)
        myrepr = ", ".join(
            "%s=%s" % (var, myvars[var])
            for var in myvars
            if not var.startswith("_") and myvars[var] is not None
        )

        return "<rules.filter.Filter(%s)>" % myrepr
