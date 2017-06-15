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
import tempfile

import yaml
from pyroute2 import IPRoute

import ndr_netcfg

THIS_DIR = os.path.dirname(os.path.abspath(__file__))

@unittest.skipIf(os.getuid() != 0, "must be root")
class NetworkConfig(unittest.TestCase):
    '''Tests the functionality of the network configurer'''

    def setUp(self):
        self._iproute = IPRoute()

        # Unfortunately, when creating dummy interfaces, you'll end up with an
        # interface named dummyX no matter what you do
        self._iproute.link('add', name='dummy0', kind='dummy')
        self._iproute.link('add', name='dummy1', kind='dummy')

        self._dummy0_idx = self._iproute.link_lookup(ifname='dummy0')[0]
        self._dummy1_idx = self._iproute.link_lookup(ifname='dummy1')[0]

    def tearDown(self):
        # Remove our dummy interfaces
        self._iproute.link('remove', index=self._dummy0_idx)
        self._iproute.link('remove', index=self._dummy1_idx)

        self._iproute.close()

    def configure_interfaces(self, config_file="/dev/null"):
        '''Sets up interfaces for most tests'''

        nc = ndr_netcfg.NetworkConfiguration(config_file)
        nc.rename_interface("dummy0", "lan127")
        nc.set_configuration_method("lan127", ndr_netcfg.InterfaceConfigurationMethods.STATIC)
        nc.add_v4_addr("lan127", "10.1.177.2", 24, "10.1.177.255")

        nc.rename_interface("dummy1", "monitor234")
        nc.set_configuration_method("monitor234", ndr_netcfg.InterfaceConfigurationMethods.STATIC)
        nc.add_v4_addr("monitor234", "10.2.177.2", 24, "10.2.177.255")

        nc.apply_configuration()
        return nc

    def test_renaming_interfaces(self):
        nc = self.configure_interfaces()

        # If everything worked as planned, we should successfully be able to get the index numbers
        # based on the new interface names

        self.assertEqual(self._dummy0_idx, self._iproute.link_lookup(ifname='lan127')[0])
        self.assertEqual(self._dummy1_idx, self._iproute.link_lookup(ifname='monitor234')[0])

    def test_serialization_of_data_to_yaml(self):
        '''Tests that data can be properly serialized to YAML, AND that only managed interfaces
        end up in the resulting YAML file'''

        try:
            fd, scratch_config = tempfile.mkstemp()
            os.close(fd) # Don't need to write anything to it

            # First we need to setup the configuration instances
            nc = self.configure_interfaces(scratch_config)

            # And write it out to the YAML file
            nc.export_configuration()

            # Now we need to read it back as YAML and make sure all the stuff we expect is there
            with open(scratch_config, 'r') as f:
                yaml_contents = yaml.safe_load(f.read())

                # We should only have one element at the moment, interfaces
                self.assertEqual(len(yaml_contents), 1)
                interfaces = yaml_contents['interfaces']

                # We should have two interfaces
                self.assertEqual(len(interfaces), 2)

                matched_lan127 = False
                matched_monitor234 = False

                for interface in interfaces:
                    if interface['name'] == 'lan127':
                        # Confirm the lan127 interface is set properly. MAC addresses are
                        # randomized so we can't compare them directly.
                        self.assertTrue(interface['method'], 'static')
                        matched_lan127 = True

                    # And again for monitor234
                    if interface['name'] == 'monitor234':
                        # Confirm the lan127 interface is set properly. MAC addresses are
                        # randomized so we can't compare them directly.
                        self.assertTrue(interface['method'], 'static')
                        matched_monitor234 = True

                # Make sure we got both things
                self.assertTrue(matched_lan127)
                self.assertTrue(matched_monitor234)

        finally:
            os.remove(scratch_config)
