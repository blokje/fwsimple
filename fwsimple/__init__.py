from __future__ import unicode_literals, print_function, absolute_import

from .firewall import Firewall
import sys


def main() -> None:
    """ Entry point """
    dry_run = "--dry-run" in sys.argv
    if dry_run:
        print("DRY RUN, NO COMMIT")
    fwsimple = Firewall("/etc/fwsimple/fwsimple.cfg", dry_run)
    fwsimple.commit()


__version__ = "0.2.2"
__author__ = "Rick Voormolen"
__email__ = "rick@voormolen.org"

if __name__ == "__main__":
    main()
