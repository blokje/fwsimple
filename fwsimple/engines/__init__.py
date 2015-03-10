from __future__ import unicode_literals, print_function, absolute_import

import warnings
import subprocess

import fwsimple.lib

def load_engine(engine):
    """ Load an engine """
    engine_name = "fwsimple.engines.%s.Engine" % engine
    try:
        return fwsimple.lib._load_class(engine_name)
    except ImportError:
        raise NotImplementedError("Engine %s is not implemented" % engine)

class BaseEngine(object):
   
    def __init__(self, firewall):
        self.firewall = firewall

    def commit(self):
        for cmd in self.__commit_cmds():
            if not self.firewall._dry_run:
                self.__commit_exec(cmd)
            else:
                print(subprocess.list2cmdline(cmd))

    def __commit_exec(self, cmd):
        """ Execute command """
        try:
            if subprocess.call(cmd) != 0:
                warnings.warn("Execution failed: " + str(cmd))
        except OSError:
            warnings.warn("Execution failed: " + str(cmd))

    def __commit_cmds(self):
        """ Yield all the commands required to commit the
            the Firewall Configuration to the system 
        
        1. Add basic firewall rules
        2. Create zones
        3. Create zone definitions
        4. Insert firewall rules
        5. Close zones
        6. Add default policies
        """

        ## Initialize firewall configurations
        for cmd in self.init():
            yield cmd

        for zone in self.firewall.zones:
            for cmd in self.zone_create(zone):
                yield cmd

        for expression in sorted(self.firewall.get_zone_expressions()):
            for cmd in self.zone_expression_create(expression):
                yield cmd

        # Insert rules
        for action in ['discard', 'reject', 'accept']:
            for rule in [rule for rule in self.firewall.rules if rule.action == action]:
                for cmd in self.rule_create(rule):
                    yield cmd

    def init(self):
        raise NotImplementedError("Function 'init' not implemented!")

    def zone_create(self, zone):
        raise NotImplementedError("Function 'zone_create' not implemented!")

    def zone_expression_create(self, zone):
        raise NotImplementedError("Function 'zone_expression_create' not implemented!")

    def rule_create(self, rule):
        raise NotImplementedError("Function 'rule_create' not implemented!")
