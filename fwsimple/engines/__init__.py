from __future__ import unicode_literals, print_function, absolute_import
from typing import Iterable, List, TYPE_CHECKING, Type

import warnings
import subprocess
import os

import fwsimple.lib
import fwsimple.constants

if TYPE_CHECKING:
    from ..xtypes import TrafficDirection, FilterAction
    from ..firewall import Firewall
    from ..rules import Filter
    from ..zone import Zone, ZoneExpression


def load_engine(engine: str) -> Type["BaseEngine"]:
    """ Load an engine """
    engine_name = "fwsimple.engines.%s.Engine" % engine
    try:
        return fwsimple.lib._load_class(engine_name)
    except ImportError:
        raise NotImplementedError("Engine %s is not implemented" % engine)


class BaseEngine(object):
    def __init__(self, firewall: "Firewall") -> None:
        self.firewall = firewall

    def commit(self) -> None:
        for cmd in self.__commit_cmds():
            if not self.firewall._dry_run:
                self.do_exec(cmd)
            else:
                print(subprocess.list2cmdline(cmd))

    def do_exec(self, cmd: List[str], warn: bool = True) -> int:
        """ Execute command """
        try:
            status = subprocess.call(cmd, stdout=open(os.devnull, "wb"))
            if warn and status != 0:
                warnings.warn("Execution failed: " + str(cmd))
            return status
        except OSError:
            warnings.warn("Execution failed: " + str(cmd))
            return -1

    def __commit_cmds(self) -> Iterable[List[str]]:
        """Yield all the commands required to commit the
            the Firewall Configuration to the system

        1. Add basic firewall rules
        2. Create zones
        3. Create zone definitions
        4. Insert firewall rules
        5. Close zones
        6. Add default policies
        """

        ## Initialize firewall configurations
        if os.path.isfile("/etc/fwsimple/pre-fwsimple") and os.access(
            "/etc/fwsimple/pre-fwsimple", os.X_OK
        ):
            yield ["/etc/fwsimple/pre-fwsimple"]

        yield from self.init()
        for zone in self.firewall.zones:
            yield from self.zone_create(zone)

        for expression in sorted(self.firewall.get_zone_expressions()):
            yield from self.zone_expression_create(expression)

        # Insert rules
        for action in ["discard", "reject", "accept"]:
            for rule in [rule for rule in self.firewall.rules if rule.action == action]:
                yield from self.rule_create(rule)

        # Close zones
        for zone in self.firewall.zones:
            yield from self.zone_close(zone)

        # Set default policies
        for direction in fwsimple.constants.DIRECTION:
            policy = self.firewall.get_default_policy(direction)
            yield from self.set_default_policy(direction, policy)

        if os.path.isfile("/etc/fwsimple/post-fwsimple") and os.access(
            "/etc/fwsimple/post-fwsimple", os.X_OK
        ):
            yield ["/etc/fwsimple/post-fwsimple"]

    def init(self) -> Iterable[List[str]]:
        raise NotImplementedError("Function 'init' not implemented!")

    def zone_create(self, zone: "Zone") -> Iterable[List[str]]:
        raise NotImplementedError("Function 'zone_create' not implemented!")

    def zone_expression_create(self, zone_expression: "ZoneExpression") -> Iterable[List[str]]:
        raise NotImplementedError("Function 'zone_expression_create' not implemented!")

    def rule_create(self, rule: "Filter") -> Iterable[List[str]]:
        raise NotImplementedError("Function 'rule_create' not implemented!")

    def set_default_policy(self, direction: "TrafficDirection", policy: "FilterAction") -> Iterable[List[str]]:
        raise NotImplementedError("Function 'set_default_policy' not implemented!")

    def zone_close(self, zone: "Zone") -> Iterable[List[str]]:
        raise NotImplementedError("Function 'zone_close' not implemented!")