#!/usr/bin/env python
try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup, find_packages

import fwsimple
import subprocess

git_version = subprocess.check_output("git rev-list HEAD --count".split(" ")).strip()

config = {
    'description': 'fwsimple',
    'author': fwsimple.__author__,
    'author_email': fwsimple.__email__,
    'version': "%s.%s" % (fwsimple.__version__, git_version),
    'install_requires': ['ipaddress'],
    'packages': find_packages(),
    'name': 'fwsimple',
    'data_files': [ 
        ( '/etc/fwsimple', [ 'config/fwsimple.cfg' ] ),
        ( '/etc/fwsimple/rules',  ['config/rules/README.md' ] ),
    ],
    'entry_points': {
        'console_scripts': [
            'fwsimple = fwsimple:main',
        ]
    }
}

setup(**config)
