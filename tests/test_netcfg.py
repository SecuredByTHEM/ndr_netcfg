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

import unittest
import os

import ndr_netcfg

THIS_DIR = os.path.dirname(os.path.abspath(__file__))

class NetworkConfig(unittest.TestCase):
    '''Tests the functionality of the network configurer'''

    def placeholder(self):
        '''Currently a placeholder test until I write the read things'''
        netcfg = ndr_netcfg.NetworkConfig('nonexistant')

