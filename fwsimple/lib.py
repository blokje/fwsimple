from __future__ import unicode_literals, print_function, absolute_import
from typing import TYPE_CHECKING, Type
if TYPE_CHECKING:
    from .xtypes import FilterAction
    from .engines import BaseEngine


# from fwsimple import constants
import importlib


class FirewallExecution(object):
    def __str__(self) -> str:
        """ Return formatted string based on execution type """
        return repr(self)

    def args_iptables(self): # type: ignore
        raise NotImplementedError("This function is not (yet) implemented")


class FirewallRule(object):
    # def is_filter(self):
    #     return isinstance(self, FirewallRuleFilter)
    action: "FilterAction"

    def is_accept(self) -> bool:
        return self.action == "accept"

    def is_reject(self) -> bool:
        return self.action == "reject"

    def is_discard(self) -> bool:
        return self.action == "discard"


def _load_class(classname: str) -> Type["BaseEngine"]:
    """ Load a class """
    (mod_name, cls) = classname.rsplit(".", 1)
    mod = importlib.import_module(mod_name)
    return getattr(mod, cls) # type: ignore
