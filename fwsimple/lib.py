from __future__ import unicode_literals, print_function, absolute_import

from fwsimple import constants
import importlib

class FirewallExecution(object):

    def __str__(self):
        """ Return formatted string based on execution type """
        args = None
        return repr(self) 
        if self._firewall.exec_type == constants.EXEC_IPTABLES:
            args = self.args_iptables()

        if not args:
            return repr(self)
        else:
            for expression in args:
                return " ".join([str(argument) for argument in expression])

    def args_iptables(self):
        raise NotImplementedError('This function is not (yet) implemented')

class FirewallRule(object):

    def is_filter(self):
        return isinstance(self, FirewallRuleFilter)

    def is_accept(self):
        return self.action == 'accept'

    def is_reject(self):
        return self.action == 'reject'

    def is_discard(self):
        return self.action == 'discard'

def _load_class(classname):
    """ Load a class """
    (mod, cls) = classname.rsplit(".", 1)
    mod = importlib.import_module(mod)
    return getattr(mod, cls)


