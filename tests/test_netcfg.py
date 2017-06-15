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


THIS_DIR = os.path.dirname(os.path.abspath(__file__))

@unittest.skipIf(os.getuid() != 0, "must be root")
class NetworkConfig(unittest.TestCase):
    '''Tests the functionality of the network configurer'''

    @classmethod
    def setUpClass(cls):
        cls._iproute = IPRoute()

        # Unfortunately, when creating dummy interfaces, you'll end up with an
        # interface named dummyX no matter what you do
        cls._iproute.link('add', name='dummy0', kind='dummy')
        cls._iproute.link('add', name='dummy1', kind='dummy')

        cls._dummy0_idx = cls._iproute.link_lookup(ifname='dummy0')[0]
        cls._dummy1_idx = cls._iproute.link_lookup(ifname='dummy1')[0]

    @classmethod
    def tearDownClass(cls):
        # Remove our dummy interfaces
        cls._iproute.link('remove', index=cls._dummy0_idx)
        cls._iproute.link('remove', index=cls._dummy1_idx)

        cls._iproute.close()

    def test_renaming_interfaces(self):
        nc = ndr_netcfg.NetworkConfiguration("/dev/null")
        nc.rename_interface("dummy0", "lan127")
        nc.set_configuration_method("lan127", "static")

        nc.rename_interface("dummy1", "monitor234")
        nc.set_configuration_method("monitor234", "static")

        nc.apply_configuration()

        print(netifaces.interfaces())