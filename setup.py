#!/usr/bin/python3
# This file is part of NDR.
#
# Copyright (C) 2017 - Secured By THEM
# Original Author: Michael Casadevall <mcasadevall@them.com>
#
# NDR is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# NDR is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with NDR.  If not, see <http://www.gnu.org/licenses/>.

from setuptools import setup, find_packages

setup(
    name="ndr_netcfg",
    version="0.1",
    packages=find_packages(exclude=("tests",)),
    install_requires=[
        'pyyaml',
        'pyroute2'
    ],
    entry_points={
        'console_scripts': [
            'ndr-network-config = ndr_netcfg.tools.shell:main',
            'ndr-network-apply = ndr_netcfg.tools.netconfig:main'
        ]
    },
    test_suite="tests"
)
