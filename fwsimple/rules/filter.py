from __future__ import unicode_literals, print_function, absolute_import

# TODO: Rename Rule and Execution
from fwsimple.lib import FirewallRule, FirewallExecution
from fwsimple import constants

import ipaddress

class Filter(FirewallRule, FirewallExecution):

    def __init__(self, name, firewall, zone, source=None, destination=None, port=None,
                 protocol='tcp', action='accept', log=False, direction='in', **options):
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

        if direction in constants.DIRECTION:
            self.direction = direction
        else:
            raise Exception(
                "Direction '%s' is not understood! (%s)" %
                (direction, self.name))

        # Public : Addresses
        if source:
            self.source = ipaddress.ip_network(source)
        else:
            self.source = None
        if destination:
            self.destination = ipaddress.ip_network(destination)
        else:
            self.destination = None

        # Public : Protocol/ports
        if not port:
            self.port = None
        elif ',' in port or '-' in port:
            self.multiport = True
            self.port = []
            ports = port.split(',')

            for port in ports:
                if '-' in port:
                    (start, end) = port.split('-')
                    self.port.append('%d:%d' % (int(start), int(end)))
                else:
                    self.port.append('%d' % int(port))
            self.port = ','.join(self.port)
        else:
            self.multiport = False
            self.port = int(port)

        self.protocol = protocol

        # Public : Actions
        if action in constants.IPTABLES_ACTIONS:
            self.action = action
        else:
            raise Exception(
                "Action '%s' is not understood! (%s)" %
                (action, self.name))

        self.log = bool(log)

        # Determine if source and destenation are both same protocol
        if self.source and self.destination:
            if self.source.version != self.destination.version:
                raise Exception(
                    'You cannot mix IPv4 and IPv6 addresses [source=%s, destination=%s] (%s)' %
                    (self.source, self.destination, self.name))

        # Determine protocol level
        self.proto = constants.PROTO_IPV4 + constants.PROTO_IPV6
        if self.source:
            if self.source.version == 4:
                self.proto -= constants.PROTO_IPV6
            elif self.source.version == 6:
                self.proto -= constants.PROTO_IPV4
        elif self.destination:
            if self.destination.version == 4:
                self.proto -= constants.PROTO_IPV6
            elif self.destination.version == 6:
                self.proto -= constants.PROTO_IPV4

    def args_iptables(self):
        iptables = ['-A', '%s_%s' %
                    (constants.DIRECTION[self.direction], self.zone)]
        iptables += ['-m', 'conntrack', '--ctstate', 'NEW']
        iptables += ['-m', 'comment', '--comment', self.name]

        if self.source:
            iptables += ['-s', str(self.source)]

        if self.destination:
            iptables += ['-d', str(self.destination)]

        if self.protocol:
            iptables += ['-p', self.protocol]

            if self.port:
                if self.multiport:
                    iptables += ['-m', 'multiport']
                iptables += ['--dport', str(self.port)]

        if self.log:
            log = iptables + \
                ['-j', 'LOG', '--log-prefix', '%s ' % self.name[0:28]]

        iptables += ['-j', constants.IPTABLES_ACTIONS[self.action]]
        if self.log:
            return [log, iptables]
        return [iptables]

    def __repr__(self):
        myvars = vars(self)
        myrepr = ", ".join(["%s=%s" % (var, myvars[var]) for var in myvars if not var.startswith('_') and myvars[var] is not None])
        return '<FirewallRuleFilter(%s)>' % myrepr


