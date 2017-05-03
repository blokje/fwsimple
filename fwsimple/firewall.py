import configparser
import glob

from fwsimple import constants, zone
import fwsimple.engines
from fwsimple.zone import Zone


class Firewall(object):

    """ The Firewall itself """

    def __init__(self, configfile, dry_run=False):
        """ Load the configuration """
        # Initialize attributes
        self.rules = []
        self.zones = [  ]
        self.ruleset_location = None
        self.config = None
        self.exec_type = None
        self._dry_run = dry_run

        self.load_config(configfile)
        self.load_zones()
        self.load_rulesets()

    def load_config(self, configfile):
        """ Read the config file and load appropriate firewall engine """
        self.config = configparser.SafeConfigParser()
        self.config.read(configfile)

        # Verify configuration
        self.ruleset_location = self.config.get('fwsimple', 'rulesets')
        try:
            self.exec_type = constants.EXEC_MAP[self.config.get('fwsimple', 'engine')]
            self.engine = fwsimple.engines.load_engine(self.config.get('fwsimple','engine'))(self)
        except KeyError:
            raise Exception('Unsupported engine!')

    def load_zones(self):
        """ Load zones and add magic zone global """
        zone_global = Zone(self, constants.GLOBAL_ZONE_NAME, None)
        zone_global.add_expression(None)
        self.zones.append(zone_global)

        for zone in self.config.items('zones'):
            self.zones.append(Zone(self, *zone))

    def has_zone(self, zone_name):
        """ Check if zone already exists """
        for zone in self.zones:
            if zone.name == zone_name:
                return True
        return False

    def has_zone_expression(self, new_expression):
        """ Check if zone expression already exists """
        for zone in self.zones:
            for expression in zone.expressions:
                if new_expression == expression:
                    return True
        return False

    def get_zone_expressions(self):
        for zone in self.zones:
            for expression in zone.expressions:
                yield expression

    def get_zone(self, name):
        for zone in self.zones:
            if zone.name == name:
                return zone

    def load_rulesets(self):
        for ruleset in sorted(glob.glob(self.ruleset_location + '/*.rule')):
            self.parse_ruleset(ruleset)

    def parse_ruleset(self, ruleset_file):
        # TODO: Move Ruleset parser to rule/__init__.py::Ruleset
        # import in function is not tidy but keep it here so we can 
        # remove it when move action is completed
        import codecs
        import os
        from . import rules
        ruleset = configparser.SafeConfigParser(defaults={'type': 'filter'})
        with codecs.open(ruleset_file, 'rb', encoding='utf-8') as ruleset_fp:
            ruleset.readfp(ruleset_fp)

        for rule in ruleset.sections():
            ruletype = ruleset.get(rule, 'type')
            name = '%s::%s' % (os.path.basename(ruleset_file), rule)
            try:
                if ruletype == 'filter':
                    firewall_rule = rules.filter.Filter(name=name, firewall=self, **dict(ruleset.items(rule)))
                    self.rules.append(firewall_rule)
            except TypeError:
                print("Error in %s" % name)

    def apply(self):
        """ Apply firewall config """
        #for runcmd in self.__execute_iptables():
        for runcmd in self.engine.apply():
            if not self._dry_run:
                if subprocess.call(runcmd) != 0:
                    print(runcmd)
            else:
                print(subprocess.list2cmdline(runcmd))

    def commit(self):
        """ Request engine to commit configuration """
        self.engine.commit()


    def get_default_policy(self, direction):
        return self.config.get('policy', direction)

## TODO: Remove this function
#    def __execute_iptables(self):
#        """ Return all commands to be executed for IPtables """
#
##        # Default configurations
#        for _ in constants.BASIC_IPTABLES_INIT:
#            yield ['iptables'] + _
#            yield ['ip6tables'] + _
#        for _ in constants.BASIC_IP4TABLES_INIT:
#            yield ['iptables'] + _
#        for _ in constants.BASIC_IP6TABLES_INIT:
#            yield ['ip6tables'] + _
#
#        # Zones will be created in IPv4 AND IPv6
#        # 1. Create zones
#        # 2. Add specific expressions
#        # 3. Add generic expressions
#
#        for zone in self.zones:
#            for creator in zone.args_iptables():
#                yield ['iptables'] + creator
#                yield ['ip6tables'] + creator
#
#        for expression in  self.get_zone(constants.GLOBAL_ZONE_NAME).expressions:
#            for creator in expression.args_iptables():
#                if expression.proto & constants.PROTO_IPV4:
#                    yield ['iptables'] + creator
#                if expression.proto & constants.PROTO_IPV6:
#                    yield ['ip6tables'] + creator
#
#               
#
#        for expression in self.get_specific_zone_expressions():
#            for creator in expression.args_iptables():
#                if expression.proto & constants.PROTO_IPV4:
#                    yield ['iptables'] + creator
#                if expression.proto & constants.PROTO_IPV6:
#                    yield ['ip6tables'] + creator
#
#        for expression in self.get_nonspecific_zone_expressions():
#            for creator in expression.args_iptables():
#                yield ['iptables'] + creator
#
#        # Insert rules
#        for action in ['discard', 'reject', 'accept']:
#            for rule in [rule for rule in self.rules if rule.action == action]:
#                args = rule.args_iptables()
#                if rule.proto & constants.PROTO_IPV4:
#                    for _ in args:
#                        yield ['iptables'] + _
#                if rule.proto & constants.PROTO_IPV6:
#                    for _ in args:
#                        yield ['ip6tables'] + _
#
#        # Closeup all zones
#        for zone in self.zones:
#            for creator in zone.args_iptables_return():
#                yield ['iptables'] + creator
#                yield ['ip6tables'] + creator
#
#        # Add default policies
#        for direction in constants.DIRECTION:
#            action = constants.IPTABLES_ACTIONS[
#                self.__get_default_policy(direction)]
#            chain = constants.IPTABLES_DIRECTION[direction]
#            cmd = ['-A', chain, '-j', action]
#            yield ['iptables'] + cmd
#            yield ['ip6tables'] + cmd
#
