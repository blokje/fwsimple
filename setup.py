#!/usr/bin/env python3
from setuptools import setup

import fwsimple
import subprocess

git_version = (
    subprocess.check_output("git rev-list HEAD --count".split(" "))
    .strip()
    .decode("ASCII")
)

import sys

install_reqs = []
if sys.version_info < (3, 3):
    install_reqs.append("ipaddress")

config = {
    "description": "fwsimple",
    "author": fwsimple.__author__,
    "author_email": fwsimple.__email__,
    "version": fwsimple.__version__,
    "install_requires": install_reqs, # Use the conditional list
    "packages": ["fwsimple", "fwsimple.rules", "fwsimple.engines"],
    "name": "fwsimple",
    "entry_points": {
        "console_scripts": [
            "fwsimple = fwsimple:main",
        ]
    },
}

setup(**config)
