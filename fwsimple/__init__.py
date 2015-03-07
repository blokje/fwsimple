#from __future__ import unicode_literals, print_function
import glob
import pprint
import ConfigParser
import os
import codecs
import ipaddress

EXEC_IPTABLES = 1
EXEC_PF = 2
EXEC_MAP = {
    'iptables': EXEC_IPTABLES,
    'pf': EXEC_PF,
}


class Firewall():

    """ The Firewall itself """

    def __init__(self, configfile):
        """ Load the configuration """
        self.rules = []
        self.zones = []

        self.load_config(configfile)
        self.load_zones()

    def load_config(self, configfile):
        self.config = ConfigParser.SafeConfigParser()
        self.config.read(configfile)

        # Verify configuration
        self.ruleset_location = self.config.get('fwsimple', 'rulesets')
        try:
            self.exec_type = EXEC_MAP[self.config.get('fwsimple', 'engine')]
        except KeyError:
            raise Exception('Unsupported engine!')

    def load_zones(self):
        for zone in self.config.items('zones'):
            self.zones.append(FirewallZone(self, *zone))

    def has_zone_expression(self, new_expression):
        for zone in self.zones:
            for expression in zone.expressions:
                if new_expression == expression:
                    return True
        return False

    def load_rulesets(self):
        for ruleset in glob.glob(self.ruleset_location + '/*.rule'):
            self.parse_ruleset(ruleset)

        for action in ['discard', 'reject', 'accept']:
            print("## %s ##" % action)
            for rule in [rule for rule in self.rules if rule.action == action]:
                print(rule)

    def parse_ruleset(self, ruleset_file):
        ruleset = ConfigParser.SafeConfigParser(defaults={'type': 'filter'})
        with codecs.open(ruleset_file, 'rb', encoding='utf-8') as ruleset_fp:
            ruleset.readfp(ruleset_fp)

        for rule in ruleset.sections():
            ruletype = ruleset.get(rule, 'type')
            name = '%s::%s' % (os.path.basename(ruleset_file), rule)
            try:
                if ruletype == 'filter':
                    fr = FirewallRuleFilter(name=name, firewall=self,
                                            **dict(ruleset.items(rule)))
                    self.rules.append(fr)
            except TypeError as e:
                print("Error in %s" % name)


class FirewallExecution():

    def __str__(self):
        """ Return formatted string based on execution type """
        args = None

        if self._firewall.exec_type == EXEC_IPTABLES:
            args = self.args_iptables()

        if not args:
            return repr(self)
        else:
            for expression in args:
                return " ".join([str(argument) for argument in expression])

    def args_iptables(self):
        raise NotImplemented('This function is not (yet) implemented')


class FirewallZone(FirewallExecution):

    """ A firewall zone will be used for initial packet filtering """

    class SubExpression():

        """ A subexpression is a small part of the zone definition """

        def __init__(self, expression):
            self.expression = expression

            # Check if expression is specific (specific zones preceed generic
            # zones)
            if ':' in self.expression:
                self.specific = True
                (self.interface, self.source) = self.expression.split(':')
            else:
                self.specific = False
                self.interface = self.expression
                self.source = None

        def __eq__(self, other):
            return ((self.interface == other.interface) and (self.source == other.source))

    def __init__(self, firewall, name, expression):
        """ Define a firewall zone """
        self.expressions = []
        self._firewall = firewall

        self.name = name
        for expr in expression.split(','):
            subexpression = self.SubExpression(expr)
            if self._firewall.has_zone_expression(subexpression):
                raise Warning(
                    'Duplicate zone definition detected (zone=%s, expression=%s)' % (self.name, expr))
            else:
                self.expressions.append(subexpression)

#    def args_iptables(self):
#        return None


class FirewallRule(FirewallExecution):

    def is_filter(self):
        return isinstance(self, FirewallRuleFilter)

    def is_accept(self):
        return self.action == 'accept'

    def is_reject(self):
        return self.action == 'reject'

    def is_discard(self):
        return self.action == 'discard'


RULE_DIRECTION_IN = 0
RULE_DIRECTION_OUT = 1
RULE_DIRECTION_FWD = 2
RULE_DIRECTION = {
    'in': RULE_DIRECTION_IN,
    'out': RULE_DIRECTION_OUT,
    'forward': RULE_DIRECTION_FWD,
}


class FirewallRuleFilter(FirewallRule):
    ACTIONS = {'accept': 'ACCEPT', 'reject': 'REJECT', 'discard': 'DROP'}
    DIRECTION = {'in': 'IN', 'out': 'OUT', 'forward': 'FWD'}

    def __init__(
        self, name, firewall, zone, source=None, destination=None, port=None,
                 protocol='tcp', action='accept', log=False, direction='in', **options):
        """ Define firewall definition """

        # Private
        self._firewall = firewall
        self._options = options

        # Public : Meta data
        self.name = name
        self.zone = zone
        if direction in self.DIRECTION:
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
        if ',' in port or '-' in port:
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
        if action in self.ACTIONS:
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

    def args_iptables(self):
        iptables = ['-A', '%s_%s' %
                    (self.DIRECTION[self.direction], self.zone)]
        iptables += ['-m', 'conntrack', '--ctstate', 'NEW']
        iptables += ['-m', 'comment', '--comment', self.name]

        if self.source:
            iptables += ['-s', self.source]

        if self.destination:
            iptables += ['-d', self.destination]

        if self.protocol:
            iptables += ['-p', self.protocol]

            if self.multiport:
                iptables += ['-m', 'multiport']
            iptables += ['--dport', self.port]

        iptables += ['-j', self.ACTIONS[self.action]]

        if self.log:
            log = iptables + \
                ['-j', 'LOG', '--log-prefix', '%s ' % self.name[0:28]]

        iptables += ['-j', self.ACTIONS[self.action]]
        if self.log:
            return [log, iptables]
        return [iptables]

    def __repr__(self):
        myvars = vars(self)
        myrepr = ", ".join(["%s=%s" % (var, myvars[var])
                           for var in myvars if not var.startswith('_') and myvars[var] is not None])
        return '<FirewallRuleFilter(%s)>' % myrepr

BASIC_IPTABLES_INIT = [
    ['-X'],    # Delete user-defined chains
    ['-F'],    # Flush default chains
    ['-Z'],    # Zero counters
    ['-A', 'INPUT', '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
    ['-A', 'FORWARD', '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
    ['-A', 'OUTPUT', '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
    ['-A', 'INPUT', '-m', 'conntrack', '--ctstate', 'INVALID', '-j', 'DROP']
]

BASIC_IP4TABLES_INIT = [
    ['-A', 'INPUT', '-p', 'icmp', '-m', 'icmp', '--icmp-type', '8', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMP] Echo Request'],
    ['-A', 'INPUT', '-p', 'icmp', '-m', 'icmp', '--icmp-type', '3/4', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMP] Fragmentation needed'],
    ['-A', 'INPUT', '-p', 'icmp', '-m', 'icmp', '--icmp-type', '3/3', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMP] Port unreachable'],
    ['-A', 'INPUT', '-p', 'icmp', '-m', 'icmp', '--icmp-type', '3/1', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMP] Host unreachable'],
    ['-A', 'INPUT', '-p', 'icmp', '-m', 'icmp', '--icmp-type', '4', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMP] Source Quench (RFC 792)']
]

BASIC_IP6TABLES_INIT = [
    ['-A', 'INPUT', '-p', '59', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[IPv6] No next header RFC2460'],
    ['-A', 'INPUT', '-p', 'icmpv6', '-m', 'icmpv6', '--icmpv6-type', '2', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMPv6] Packet too big'],
    ['-A', 'INPUT', '-p', 'icmpv6', '-m', 'icmpv6', '--icmpv6-type', '3', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMPv6] Time exceeded'],
    ['-A', 'INPUT', '-p', 'icmpv6', '-m', 'icmpv6', '--icmpv6-type', '133', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMPv6] Router sollicitation'],
    ['-A', 'INPUT', '-p', 'icmpv6', '-m', 'icmpv6', '--icmpv6-type', '134', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMPv6] Router advertisement'],
    ['-A', 'INPUT', '-p', 'icmpv6', '-m', 'icmpv6', '--icmpv6-type', '135', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMPv6] Neighbor sollicitation'],
    ['-A', 'INPUT', '-p', 'icmpv6', '-m', 'icmpv6', '--icmpv6-type', '136', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMPv6] Neighbor advertisement'],
    ['-A', 'INPUT', '-p', 'icmpv6', '-m', 'icmpv6', '--icmpv6-type', '128', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMPv6] Echo Request']
] 
# for line in BASIC_IPTABLES_INIT+BASIC_IP4TABLES_INIT:
#    print(" ".join(line))
fw = Firewall('/home/rick/Source/fwsimple/config/fwsimple.cfg')
# fw.load_rulesets()
# print("COMMIT")
# print("""#
#*filter
#:INPUT ACCEPT [48:7832]
#:FORWARD ACCEPT [0:0]
#:OUTPUT ACCEPT [42:5582]
#:IN_all - [0:0]
#:IN_tunnels - [0:0]
#:IN_lan - [0:0]
#:IN_wan - [0:0]
#:OUT_all - [0:0]
#:OUT_tunnels - [0:0]
#:OUT_lan - [0:0]
#:OUT_wan - [0:0]
#""")
