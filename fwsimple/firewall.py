import configparser
import glob
from typing import Iterator, List, Optional, TYPE_CHECKING, cast

from fwsimple import constants, zone
import fwsimple.engines
from fwsimple.zone import Zone

if TYPE_CHECKING:
    from .xtypes import FilterAction
    from .rules.filter import Filter
    from .zone import ZoneExpression


class Firewall(object):

    """ The Firewall itself """

    def __init__(self, configfile: str, dry_run: bool = False) -> None:
        """ Load the configuration """
        # Initialize attributes
        self.rules: List["Filter"] = []
        self.zones: List["Zone"] = []
        # self.ruleset_location: Optional[str] = None
        self.config = configparser.SafeConfigParser()
        self.exec_type: Optional[int] = None
        self._dry_run = dry_run

        self.load_config(configfile)
        self.load_zones()
        self.load_rulesets()

    def load_config(self, configfile: str) -> None:
        """ Read the config file and load appropriate firewall engine """
        self.config.read(configfile)

        # Verify configuration
        self.ruleset_location = self.config.get("fwsimple", "rulesets")
        try:
            self.exec_type = constants.EXEC_MAP[self.config.get("fwsimple", "engine")]
            self.engine = fwsimple.engines.load_engine(
                self.config.get("fwsimple", "engine")
            )(self)
        except KeyError:
            raise Exception("Unsupported engine!")

    def load_zones(self) -> None:
        """ Load zones and add magic zone global """
        zone_global = Zone(self, constants.GLOBAL_ZONE_NAME, None)
        zone_global.add_expression(None)
        self.zones.append(zone_global)

        for zone in self.config.items("zones"):
            self.zones.append(Zone(self, *zone))

    def has_zone(self, zone_name: str) -> bool:
        """ Check if zone already exists """
        return any(zone.name == zone_name for zone in self.zones)

    def has_zone_expression(self, new_expression: "ZoneExpression") -> bool:
        """ Check if zone expression already exists """
        for zone in self.zones:
            for expression in zone.expressions:
                if new_expression == expression:
                    return True
        return False

    def get_zone_expressions(self) -> Iterator["ZoneExpression"]:
        for zone in self.zones:
            yield from zone.expressions

    def get_zone(self, name: str) -> Optional["Zone"]:
        for zone in self.zones:
            if zone.name == name:
                return zone
        return None

    def load_rulesets(self) -> None:
        for ruleset in sorted(glob.glob(self.ruleset_location + "/*.rule")):
            self.parse_ruleset(ruleset)

    def parse_ruleset(self, ruleset_file: str) -> None:
        # TODO: Move Ruleset parser to rule/__init__.py::Ruleset
        # import in function is not tidy but keep it here so we can
        # remove it when move action is completed
        import codecs
        import os
        from . import rules

        ruleset = configparser.SafeConfigParser(defaults={"type": "filter"})
        with codecs.open(ruleset_file, "rb", encoding="utf-8") as ruleset_fp:
            ruleset.readfp(ruleset_fp)

        for rule in ruleset.sections():
            ruletype = ruleset.get(rule, "type")
            name = "%s::%s" % (os.path.basename(ruleset_file), rule)
            try:
                if ruletype == "filter":
                    firewall_rule = rules.filter.Filter(
                        name=name, firewall=self, **dict(ruleset.items(rule))  # type: ignore
                    )
                    self.rules.append(firewall_rule)
            except TypeError as exc:
                raise Exception("Error in %s: %s" % (name, exc))

    # def apply(self):
    #     """ Apply firewall config """
    #     # for runcmd in self.__execute_iptables():
    #     for runcmd in self.engine.apply():
    #         if not self._dry_run:
    #             if subprocess.call(runcmd) != 0:
    #                 print(runcmd)
    #         else:
    #             print(subprocess.list2cmdline(runcmd))

    def commit(self) -> None:
        """ Request engine to commit configuration """
        self.engine.commit()

    def get_default_policy(self, direction: str) -> "FilterAction":
        policy = self.config.get("policy", direction)
        if policy not in ["accept", "reject", "discard"]:
            raise Exception(
                f"Policy invalid '{policy}' not allowed. Accepted values: accept, reject, discard"
            )
        return cast("FilterAction", policy)
