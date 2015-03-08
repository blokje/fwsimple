from __future__ import unicode_literals, print_function, absolute_import

from . import constants
import glob
import pprint
import ConfigParser
import os
import codecs
import ipaddress
import subprocess


class Firewall(object):

    """ The Firewall itself """

    def __init__(self, configfile):
        """ Load the configuration """
        # Initialize attributes
        self.rules = []
        self.zones = []
        self.ruleset_location = None
        self.config = None
        self.exec_type = None

        self.load_config(configfile)
        self.load_zones()
        self.load_rulesets()

    def load_config(self, configfile):
        self.config = ConfigParser.SafeConfigParser()
        self.config.read(configfile)

        # Verify configuration
        self.ruleset_location = self.config.get('fwsimple', 'rulesets')
        try:
            self.exec_type = constants.EXEC_MAP[
                self.config.get('fwsimple', 'engine')]
        except KeyError:
            raise Exception('Unsupported engine!')

    def load_zones(self):
        for zone in self.config.items('zones'):
            self.zones.append(FirewallZone(self, *zone))

    def has_zone(self, zone_name):
        for zone in self.zones:
            if zone.name == zone_name:
                return True
        return False

    def has_zone_expression(self, new_expression):
        for zone in self.zones:
            for expression in zone.expressions:
                if new_expression == expression:
                    return True
        return False

    def get_specific_zone_expressions(self):
        for expression in self.get_zone_expressions(True):
            yield expression

    def get_nonspecific_zone_expressions(self):
        for expression in self.get_zone_expressions(False):
            yield expression

    def get_zone_expressions(self, specific=None):
        for zone in self.zones:
            for expression in zone.expressions:
                if specific is None:
                    yield expression
                elif expression.specific is specific:
                    yield expression

    def load_rulesets(self):
        for ruleset in sorted(glob.glob(self.ruleset_location + '/*.rule')):
            self.parse_ruleset(ruleset)

    def parse_ruleset(self, ruleset_file):
        ruleset = ConfigParser.SafeConfigParser(defaults={'type': 'filter'})
        with codecs.open(ruleset_file, 'rb', encoding='utf-8') as ruleset_fp:
            ruleset.readfp(ruleset_fp)

        for rule in ruleset.sections():
            ruletype = ruleset.get(rule, 'type')
            name = '%s::%s' % (os.path.basename(ruleset_file), rule)
            try:
                if ruletype == 'filter':
                    firewall_rule = FirewallRuleFilter(name=name, firewall=self, **dict(ruleset.items(rule)))
                    self.rules.append(firewall_rule)
            except TypeError:
                print("Error in %s" % name)

    def apply(self):
        """ Apply firewall config """
        for runcmd in self.__execute_iptables():
            if subprocess.call(runcmd) != 0:
                print(runcmd)

    def __get_default_policy(self, direction):
        return self.config.get('policy', direction)

    def __execute_iptables(self):
        """ Return all commands to be executed for IPtables """

        # Default configurations
        for _ in constants.BASIC_IPTABLES_INIT:
            yield ['iptables'] + _
            yield ['ip6tables'] + _
        for _ in constants.BASIC_IP4TABLES_INIT:
            yield ['iptables'] + _
        for _ in constants.BASIC_IP6TABLES_INIT:
            yield ['ip6tables'] + _

        # Zones will be created in IPv4 AND IPv6
        # 1. Create zones
        # 2. Add specific expressions
        # 3. Add generic expressions

        for zone in self.zones:
            for creator in zone.args_iptables():
                yield ['iptables'] + creator
                yield ['ip6tables'] + creator

        for expression in self.get_specific_zone_expressions():
            for creator in expression.args_iptables():
                if expression.proto & constants.PROTO_IPV4:
                    yield ['iptables'] + creator
                if expression.proto & constants.PROTO_IPV6:
                    yield ['ip6tables'] + creator

        for expression in self.get_nonspecific_zone_expressions():
            for creator in expression.args_iptables():
                yield ['iptables'] + creator

        # Insert rules
        for action in ['discard', 'reject', 'accept']:
            for rule in [rule for rule in self.rules if rule.action == action]:
                args = rule.args_iptables()
                if rule.proto & constants.PROTO_IPV4:
                    for _ in args:
                        yield ['iptables'] + _
                if rule.proto & constants.PROTO_IPV6:
                    for _ in args:
                        yield ['ip6tables'] + _

        # Closeup all zones
        for zone in self.zones:
            for creator in zone.args_iptables_return():
                yield ['iptables'] + creator
                yield ['ip6tables'] + creator

        # Add default policies
        for direction in constants.DIRECTION:
            action = constants.IPTABLES_ACTIONS[
                self.__get_default_policy(direction)]
            chain = constants.IPTABLES_DIRECTION[direction]
            cmd = ['-A', chain, '-j', action]
            yield ['iptables'] + cmd
            yield ['ip6tables'] + cmd


class FirewallExecution(object):

    def __str__(self):
        """ Return formatted string based on execution type """
        args = None

        if self._firewall.exec_type == constants.EXEC_IPTABLES:
            args = self.args_iptables()

        if not args:
            return repr(self)
        else:
            for expression in args:
                return " ".join([str(argument) for argument in expression])

    def args_iptables(self):
        raise NotImplementedError('This function is not (yet) implemented')


class FirewallZone(FirewallExecution):

    """ A firewall zone will be used for initial packet filtering """

    class SubExpression(FirewallExecution):

        """ A subexpression is a small part of the zone definition """

        def __init__(self, firewall, zone, expression):
            self._firewall = firewall
            self._zone = zone
            self.expression = expression

            # Check if expression is specific (specific zones preceed generic
            # zones)
            if ':' in self.expression:
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

    def __init__(self, firewall, name, expression):
        """ Define a firewall zone """
        self.expressions = []
        self._firewall = firewall

        self.name = name
        for expr in expression.split(','):
            subexpression = self.SubExpression(self._firewall, self, expr)
            if self._firewall.has_zone_expression(subexpression):
                raise Warning(
                    'Duplicate zone definition detected (zone=%s, expression=%s)' % (self.name, expr))
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


class FirewallRule(object):

    def is_filter(self):
        return isinstance(self, FirewallRuleFilter)

    def is_accept(self):
        return self.action == 'accept'

    def is_reject(self):
        return self.action == 'reject'

    def is_discard(self):
        return self.action == 'discard'


class FirewallRuleFilter(FirewallRule, FirewallExecution):

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
            raise Warning('Zone %s is not defined!' % zone)

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


class FirewallRuleNAT(FirewallRule):
    pass


def main():
    """ Entry point """
    fwsimple = Firewall('/etc/fwsimple/fwsimple.cfg')
    fwsimple.apply()


__version__ = '0.1'
__author__ = 'Rick Voormolen'
__email__ = 'rick@voormolen.org'
