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
import os
import argparse
import ipaddress
import subprocess
import shlex

import yaml
from pyroute2 import IPRoute

CFG_METHODS = ['static', 'dhcp']

class NetworkConfiguration(object):

    '''Holds configuration information for NDR'''

    def __init__(self, ndr_netcfg_config):
        self.config = ndr_netcfg_config
        self.netlink = IPRoute()
        self.raw_ifaces = None
        self.ifaces = {}

        # Refers to the configuration that we want
        self.nic_configuration = {}
        self.refresh()

        # If the config file exists, load it
        if os.path.isfile(self.config):
            self.import_configuration()

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
            self.nic_configuration[mac_address]['monitor'] = False
            self.nic_configuration[mac_address]['method'] = "dhcp" # Default to DHCP configuration

        return self.nic_configuration[mac_address]

    def get_nic_config_by_name(self, name):
        '''Retrieves the NIC configuration by interface name.abs

        If its not found, an error is raised as this should only be used for managed
        interfaces'''

        for mac, values in self.nic_configuration.items():
            if values['name'] == name:
                return self.nic_configuration[mac]

        raise ValueError("Interface not found")

    def set_configuration_method(self, interface, method):
        '''Configures how an interface is configured'''
        if method not in CFG_METHODS:
            raise ValueError("Unknown configuration method")

        cfg = self.get_nic_config_by_name(interface)
        cfg['method'] = method

    def add_v4_addr(self, interface, address, cidr, broadcast):
        '''Add an address to an interface. Static configuration only'''
        cfg = self.get_nic_config_by_name(interface)

        if 'v4_addrs' not in cfg:
            cfg['v4_addrs'] = []

        cfg['v4_addrs'].append({
            'address': address,
            'cidr': cidr,
            'broadcast': broadcast
        })

    def rename_interface(self, old_name, new_name):
        '''Updates the configuration dict to the interface name'''

        if old_name not in self.ifaces:
            raise ValueError("Interface not found!")

        nic = self.get_nic_config(self.ifaces[old_name]['mac_address'])
        nic['name'] = new_name

    def apply_configuration(self, oneshot=False):
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

            # Bring up the interface if we're not a monitor port
            if values['method'] == 'dhcp':
                dhcpcd_cmdline = ['dhcpcd', '-w']

                # If we're a oneshot, invoke dhcpcd as a oneshot
                if oneshot is True:
                    dhcpcd_cmdline += ['-1']

                print("Configuring DHCP on", values['name'])
                dhcpcd_process = subprocess.run(
                    args=dhcpcd_cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    check=False)

                # This should rarely if ever happen. If we don't have a DHCP server handy, we'll
                # end up with a link local access and the client should return. This will only 
                # happen if IPv4LL fails

                if dhcpcd_process.returncode != 0:
                    print("failed to recieve an IP address!")
                    return False
                return True

            if values['method'] == 'static':
                if 'v4_addrs' not in values:
                    raise ValueError("Static configuration, but no addresses set!")


                for addr in values['v4_addrs']:
                    # Convert addr to an IP address object. This validates them
                    ip_addr = ipaddress.ip_address(addr['address'])
                    broadcast_addr = ipaddress.ip_address(addr['broadcast'])

                    # This isn't correct for IPv4 networks that !
                    if ip_addr.version == 4:
                        self.netlink.addr(
                            'add',
                            index=iface['index'],
                            address=ip_addr.compressed,
                            broadcast=broadcast_addr.compressed,
                            prefixlen=int(addr['cidr'])
                        )

    def import_configuration(self):
        with open(self.config, 'r') as f:
            self.nic_configuration = yaml.safe_load(f.read())

    def export_configuration(self):
        cfg_yaml = yaml.dump(self.nic_configuration)
        with open(self.config, 'w') as f:
            f.write(cfg_yaml)

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
                    self.export_configuration()

                if args.command == 'set':
                    # Set a configuration variable
                    pass

                if args.command == 'done':
                    done = True

                if args.command == 'help':
                    print()
                    parser.print_help()
            except ValueError as e:
                print("ERROR:", sys.exc_info()[1])
