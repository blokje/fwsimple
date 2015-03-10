from __future__ import unicode_literals, print_function, absolute_import

from .firewall import Firewall

def main():
    """ Entry point """
    fwsimple = Firewall('/etc/fwsimple/fwsimple.cfg')
    fwsimple.commit()

__version__ = '0.1'
__author__ = 'Rick Voormolen'
__email__ = 'rick@voormolen.org'
