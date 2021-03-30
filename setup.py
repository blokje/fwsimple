#!/usr/bin/env python3
from setuptools import setup

import fwsimple
import subprocess

git_version = subprocess.check_output("git rev-list HEAD --count".split(" ")).strip().decode('ASCII')

config = {
    'description': 'fwsimple',
    'author': fwsimple.__author__,
    'author_email': fwsimple.__email__,
    'version': fwsimple.__version__,
    'install_requires': ['ipaddress'],
    'packages': ['fwsimple', 'fwsimple.rules', 'fwsimple.engines'],
    'name': 'fwsimple',
    'data_files': [
        ( '/etc/systemd/system', ['init/fwsimple.service'] ),
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
