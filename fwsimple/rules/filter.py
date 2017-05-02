from __future__ import unicode_literals, print_function, absolute_import

# TODO: Rename Rule and Execution
from fwsimple.lib import FirewallRule, FirewallExecution
from fwsimple import constants

import ipaddress

class Filter(FirewallRule, FirewallExecution):

    def __init__(self, name, firewall, zone, source=None, destination=None, port=None,
                 protocol='tcp', action='accept', log=False, direction='in', country=None, **options):
        """ Define firewall definition """

        # Private
        self._firewall = firewall
        self._options = options

        # Public : Meta data
        self.name = name

        if self._firewall.has_zone(zone):
            self.zone = zone
        else:
            raise Warning('Zone %s is not defined! (%s)' % (zone, self.name))

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
            raise Exception(
                "Action '%s' is not understood! (%s)" %
                (action, self.name))

        self.log = bool(log)

    def set_direction(self, direction):
        """ Set rule direction """
        if direction in constants.DIRECTION:
            self.direction = direction
        else:
            raise Exception(
                "Direction '%s' is not understood! (%s)" %
                (direction, self.name))

    def set_source(self, source = None):
        """ Set source address(es) """
        if source:
            self.source = [ ipaddress.ip_network(address.strip()) for address in source.split(",") ]
        else:
            self.source = None

    def set_destination(self, destination = None):
        """ Set destination address(es) """
        if destination:
            self.destination = [ ipaddress.ip_network(address.strip()) for address in destination.split(",") ]
        else:
            self.destination = None

    def get_source_destinations(self):
        """ Yields all possible source/destination combinations """
        if self.source and self.destination:
            for source in self.source:
                for destination in self.destination:
                    if source.version == destination.version:
                        yield(source, destination)

        elif self.source:
            for source in self.source:
                yield (source, None)

        elif self.destination:
            for destination in self.destination:
                yield (None, destination)

        else:
            yield(None, None)

    def set_port(self, port = None):
        # Public : Protocol/ports
        if not port:
            self.port = None
        else:
            self.port = [ port for port in port.split(',') ]

    def set_country(self, country = None):
        if not country:
            self.country = None
        else:
            self.country = country

    @property
    def multiport(self):
        if self.port:
            if len(self.port) == 1:
                if '-' in self.port[0]:
                    return True
                else:
                    return False
            else:
                return True
        else:
            return False

    def __repr__(self):
        myvars = vars(self)
        myrepr = ", ".join(["%s=%s" % (var, myvars[var]) for var in myvars if not var.startswith('_') and myvars[var] is not None])
        return '<rules.filter.Filter(%s)>' % myrepr


