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

import sys
import argparse
import ipaddress
import shlex

from pyroute2 import IPRoute

class NetworkConfiguration(object):

    '''Holds configuration information for NDR'''

    def __init__(self, ndr_config):
        self.config = ndr_config
        self.netlink = IPRoute()
        self.raw_ifaces = None
        self.ifaces = {}
        # Refers to the configuration that we want
        self.nic_configuration = {}

        self.refresh()

    def refresh(self):
        '''Refreshes the iface table'''
        self.raw_ifaces = self.netlink.get_links()
        self.ifaces = {}

        ifaces = {}
        for raw_iface in self.raw_ifaces:
            name = raw_iface.get_attr('IFLA_IFNAME')

            iface = {}
            iface['index'] = raw_iface['index']
            iface['state'] = raw_iface.get_attr('IFLA_OPERSTATE')
            iface['mac_address'] = raw_iface.get_attr('IFLA_ADDRESS')
            iface['ip_addresses'] = []

            # Get the addrs per interface
            addrs = self.netlink.get_addr(index=raw_iface['index'])
            for addr in addrs:
                ip_addresses = ipaddress.ip_address(
                    addr.get_attr('IFA_ADDRESS'))

                # We probably need to get more info here in the future
                iface['ip_addresses'].append(ip_addresses)

            self.ifaces[name] = iface

    def print_interfaces(self):
        '''Dumps the network interfaces to stdout'''
        print("\n=== Linux Network Configuration ===")

        for name, values in self.ifaces.items():
            print("\nInterface:", name)
            print("State:", values['state'])
            print("MAC Address:", values['mac_address'])

            # Only print addresses if we have them
            if values['state'] != 'DOWN':
                print("Addresses:")
                for addr in values['ip_addresses']:
                    print("  ", addr.compressed)

            # Check if we know about this interface
            if values['mac_address'] in self.nic_configuration:
                our_cfg = self.nic_configuration[values['mac_address']]

                print("Interface is configured. Settings applied at commit:")
                if our_cfg['name'] != name:
                    print("  Rename to:", our_cfg['name'])
            else:
                print("Interface is NOT configured for NDR")

    def get_linux_iface_by_mac(self, mac_address):
        '''Gets the interface dict by MAC address'''
        for name, values in self.ifaces.items():
            if values['mac_address'] == mac_address:
                return name

        return None  # Not found

    def get_nic_config(self, mac_address):
        '''Retrieves the NIC configuration based on MAC address,

        If it's not found, its created automatically'''

        if mac_address not in self.nic_configuration:
            self.nic_configuration[mac_address] = {}

        return self.nic_configuration[mac_address]

    def rename_interface(self, old_name, new_name):
        '''Updates the configuration dict to the interface name'''

        if old_name not in self.ifaces:
            raise ValueError("Interface not found!")

        nic = self.get_nic_config(self.ifaces[old_name]['mac_address'])
        nic['name'] = new_name

    def apply_configuration(self):
        '''Applies the configuration from the network dict'''

        for nic, values in self.nic_configuration.items():
            iface_name = self.get_linux_iface_by_mac(nic)
            iface = self.ifaces[iface_name]

            if iface_name != values['name']:
                print("Renaming", iface_name, "to", values['name'])

                # Interface must be brought down to rename it
                self.netlink.link('set', index=iface['index'], state='down')
                self.netlink.link(
                    'set', index=iface['index'], ifname=values['name'])
                self.netlink.link('set', index=iface['index'], state='up')

    def interactive_configuration(self):
        '''Interactively reconfigures the network'''
        done = False

        # Set up our argument parser
        parser = argparse.ArgumentParser(
            description="Network Configuration", add_help=False, usage=argparse.SUPPRESS)
        subparsers = parser.add_subparsers(
            title="Commands", metavar=" ", dest='command')

        subparsers.add_parser('help', help='prints configuring')

        rename_cmd = subparsers.add_parser('rename', help='renames interface')
        rename_cmd.add_argument('old_name', help='interface to rename')
        rename_cmd.add_argument('new_name', help='new name of the interface')

        set_cmd = subparsers.add_parser('set', help='sets interfact parameters')
        set_cmd.add_argument('interface', help='interface to set info on')
        set_cmd.add_argument('field', help='setting to edit')
        set_cmd.add_argument('value', help='value to set the field to')

        subparsers.add_parser(
            'commit', help='commits configuration changes to disk')
        subparsers.add_parser('done', help='finishes configuring')
        subparsers.add_parser('list', help='lists interfaces')

        self.print_interfaces()

        while done is False:

            command = input("ndr_network> ")
            args = None

            try:
                args = parser.parse_args(shlex.split(command))

            # argparse will try to exit the program, catch that and continue
            except SystemExit:
                print('unknown command: ', command)
                print('type \'help\' for help')
                continue

            try:
                if args.command == 'list':
                    self.print_interfaces()

                if args.command == 'rename':
                    self.rename_interface(args.old_name, args.new_name)

                if args.command == 'commit':
                    # self.write_configuration()
                    self.apply_configuration()

                if args.command == 'set':
                    # Set a configuration variable
                    pass

                if args.command == 'help':
                    print()
                    parser.print_help()
            except ValueError as e:
                print("ERROR:", sys.exc_info()[1])
