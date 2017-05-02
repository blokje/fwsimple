from __future__ import unicode_literals, print_function, absolute_import

import warnings
import subprocess
import os

import fwsimple.lib
import fwsimple.constants

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
                self.do_exec(cmd)
            else:
                print(subprocess.list2cmdline(cmd))

    def do_exec(self, cmd, warn = True):
        """ Execute command """
        try:
            status = subprocess.call(cmd, stdout=open(os.devnull,'wb'))
            if warn and status != 0:
                warnings.warn("Execution failed: " + str(cmd))
            return status
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
        if os.path.isfile("/etc/fwsimple/pre-fwsimple") and os.access("/etc/fwsimple/pre-fwsimple", os.X_OK):
            yield [ "/etc/fwsimple/pre-fwsimple" ]

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

        # Close zones
        for zone in self.firewall.zones:
            for cmd in self.zone_close(zone):
                yield cmd

        # Set default policies
        for direction in fwsimple.constants.DIRECTION:
            policy = self.firewall.get_default_policy(direction)
            for cmd in self.set_default_policy(direction, policy):
                yield cmd

        if os.path.isfile("/etc/fwsimple/post-fwsimple") and os.access("/etc/fwsimple/post-fwsimple", os.X_OK):
            yield [ "/etc/fwsimple/post-fwsimple" ]


    def init(self):
        raise NotImplementedError("Function 'init' not implemented!")

    def zone_create(self, zone):
        raise NotImplementedError("Function 'zone_create' not implemented!")

    def zone_expression_create(self, zone):
        raise NotImplementedError("Function 'zone_expression_create' not implemented!")

    def rule_create(self, rule):
        raise NotImplementedError("Function 'rule_create' not implemented!")

    def set_default_policy(self, direction, policy):
        raise NotImplementedError("Function 'set_default_policy' not implemented!")
