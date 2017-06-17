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
import logging
import logging.handlers
from socket import AF_INET, AF_INET6

from enum import Enum
import yaml
from pyroute2 import IPRoute

'''Handles network configuration for NDR, as well allowing reporting and gathering of interface
information for automatically configuring network scan utilities.

This class is not well optimized as it makes multiple RTNetLink socket calls; for our purposes, it
works well enough for now, but at some point, we should likely rewrite it to use IPDB or at least
use a single socket per class instance.'''

class InterfaceConfigurationMethods(Enum):
    '''Different methods on how an interface can be configured'''
    NONE = 'none'
    DHCP = 'dhcp'
    STATIC = 'static'

class IPAddressConfig(object):
    '''IP configuration object'''
    def __init__(self, ip_addr, prefixlen):
        self.ip_addr = ipaddress.ip_address(ip_addr)
        self.prefixlen = int(prefixlen)

    def to_dict(self):
        '''Prepares an IPv4 address for serialization'''
        ip_addr_dict = {}
        ip_addr_dict['ip_addr'] = self.ip_addr.compressed
        ip_addr_dict['prefixlen'] = self.prefixlen

        return ip_addr_dict

    @classmethod
    def from_dict(cls, ip_addr_dict):
        '''Creates the Addr object from a dictionary'''
        return IPAddressConfig(ip_addr_dict['ip_addr'],
                               ip_addr_dict['prefixlen'])

    def ip_network(self):
        '''Returns an IPNetwork object of the network/submask'''

        # ipaddress will strip off the last bits and return the correct network for us
        # automatically

        ip_net_str = self.ip_addr.compressed + "/" + str(self.prefixlen)
        return ipaddress.ip_network(ip_net_str, strict=False)

class InterfaceConfiguration(object):
    '''Holds information relating to the interfaces configured by ndr-netcfg'''

    def __init__(self, logger, name, mac_address):
        self.logger = logger
        self.name = name
        self.mac_address = mac_address
        self.method = InterfaceConfigurationMethods.NONE
        self.static_addrs = []
        self.managed = False

        # State information gotten from the kernel
        self.state = None
        self.current_name = None
        self.current_ip_addresses = []

    def refresh(self):
        '''Gets information about this device from the Linux kernel'''
        # Open a netlink socket
        netlink = IPRoute()
        raw_ifaces = netlink.get_links()

        for raw_iface in raw_ifaces:
            if raw_iface.get_attr('IFLA_ADDRESS') == self.mac_address:
                index = raw_iface['index']
                self.state = raw_iface.get_attr('IFLA_OPERSTATE')
                self.current_name = raw_iface.get_attr('IFLA_IFNAME')
                self.mac_address = raw_iface.get_attr('IFLA_ADDRESS')

                # Get the addrs per interface
                addrs = netlink.get_addr(index=index)
                for addr in addrs:
                    nic_ip_address = ipaddress.ip_address(
                        addr.get_attr('IFA_ADDRESS'))

                    # Getting the netmask is somewhat more involved unfortunately. Under Linux
                    # the netmask is NOT stored with the interface, but in the routing table
                    # which is not connected to the interface at all. We need the netmask
                    # to know which hosts we can see on a level 2 segment scan with nmap, as well
                    # as what we should expect to see on a ND probe with NMAP.

                    # To do this, we need to pull the network routing table, and walk it. For every
                    # configured IP address, we'll find multiple routing entries:
                    #
                    # The first will be a /32 (v4) or /128 (v6) referring to ourselves so that
                    # loopback works. We'll also find a broadcast route like this
                    #
                    # Secondly, we'll also have one entry per gateway with a dst_len of 0. We'll
                    # ignore these as these are global and not per interface
                    #
                    # Thirdly, we'll have our network and it's netmask
                    #
                    # Routing table entries have a preferred src (PREFSRC) value which may or may
                    # not be set saying which IP is preferred when using this route. This is a 
                    # trap, we can't use this value because in multihoming scenarios, this won't
                    # get the information we want

                    if nic_ip_address.version == 4:
                        self_prefixlen = 32
                        routing_table = netlink.get_routes(family=AF_INET)
                    else: # v6
                        self_prefixlen = 128
                        routing_table = netlink.get_routes(family=AF_INET6)

                    for route in routing_table:
                        # Filter out gateway routes
                        if route.get_attr('RTA_GATEWAY') is not None:
                            continue

                        if 'dst_len' not in route:
                            continue

                        dst_len = route['dst_len']
                        if dst_len == self_prefixlen or dst_len == 0:
                            continue # Self or default

                        # Filter out the network if its a self address, or len of 0
                        rta_dst = route.get_attr('RTA_DST')
                        if rta_dst is None:
                            continue

                        rta_dst += "/" + str(dst_len)
                        route_ipnet = ipaddress.ip_network(rta_dst, strict=True)

                        # Filter out link local addresses
                        if route_ipnet.is_link_local:
                            continue

                        if nic_ip_address in route_ipnet:
                            # We've got a winner!
                            #print("Got network match. Interface", self.name, " ", str(rta_dst))

                            # Create an IP address object and store it
                            ip_obj = IPAddressConfig(str(nic_ip_address), dst_len)
                            self.current_ip_addresses.append(ip_obj)

        # And clean up after ourselves
        netlink.close()

    def add_static_addr(self, ip_addr, prefixlen):
        '''Adds a static IPv4 address to this interface'''
        static_addr = IPAddressConfig(ip_addr, prefixlen)
        self.static_addrs.append(static_addr)

    def apply_configuration(self, oneshot=False):
        if self.managed == False:
            raise ValueError("Can't apply configuration on unmanaged interface")

        netlink = IPRoute()
        index = netlink.link_lookup(ifname=self.current_name)[0]

        if self.current_name != self.name:
            self.logger.info("Renaming %s to %s", self.current_name, self.name)

            # Interface must be brought down to rename it
            netlink.link('set', index=index, state='down')
            netlink.link('set', index=index, ifname=self.name)
            netlink.link('set', index=index, state='up')

        # Bring up the interface if we're not a monitor port
        if self.method == InterfaceConfigurationMethods.DHCP:
            dhcpcd_cmdline = ['dhcpcd', '-w']

            # If we're a oneshot, invoke dhcpcd as a oneshot
            if oneshot is True:
                dhcpcd_cmdline += ['-1']

            self.logger.info("Configuring DHCP on %s", self.name)
            dhcpcd_process = subprocess.run(
                args=dhcpcd_cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False)

            # This should rarely if ever happen. If we don't have a DHCP server handy, we'll
            # end up with a link local access and the client should return. This will only 
            # happen if IPv4LL fails

            if dhcpcd_process.returncode != 0:
                self.logger.error("failed to recieve an IP address!")
                return False
            return True

        if self.method == InterfaceConfigurationMethods.STATIC:
            if len(self.static_addrs) == 0:
                raise ValueError("Static configuration, but no addresses set!")


            for address in self.static_addrs:
                netlink.addr(
                    'add',
                    index=index,
                    address=address.ip_addr.compressed,
                    prefixlen=int(address.prefixlen)
                )

        netlink.close()

        # Refresh ourselves
        self.refresh()

    def to_dict(self):
        '''Stored configuration data to dictionary form'''
        interface_dict = {}
        interface_dict['name'] = self.name
        interface_dict['method'] = self.method.value

        # MAC addresses aren't technically configurable, but we cna use them as a relative 
        # simple UUID to identify each interface and help for matching on the next bringup
        interface_dict['mac_address'] = self.mac_address

        # If we're statically configured, save our addresses for save/reload
        v4_addrs = []
        if self.method == InterfaceConfigurationMethods.STATIC:
            for static_v4_addr in self.static_addrs:
                v4_addrs.append(static_v4_addr.to_dict())

            interface_dict['v4_addresses'] = v4_addrs

        return interface_dict

    def from_dict(self, interface_dict):
        '''Restores configuration data from dictionary form'''

        if interface_dict['mac_address'] != self.mac_address:
            raise ValueError("MAC Address mismatch! Refusing to apply configuration")

        # An interface is considered managed if we load it from a dict
        self.managed = True
        self.name = interface_dict['name']
        self.method = InterfaceConfigurationMethods(interface_dict['method'])

        if self.method == InterfaceConfigurationMethods.STATIC:
            for v4_addrs in interface_dict['v4_addresses']:
                self.static_addrs.append(
                    IPAddressConfig.from_dict(v4_addrs)
                )

class NetworkConfiguration(object):

    '''Holds configuration information for NDR'''

    def __init__(self, ndr_netcfg_config, logger=None):
        self.config = ndr_netcfg_config
        self.raw_ifaces = None

        # Log to a logger if one is manually specified, otherwise to syslog by default
        if logger is not None:
            self.logger = logger
        else:
            # Setup logging ourselves
            logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
            logger = logging.getLogger(name=__name__)
            logger.setLevel(logging.DEBUG)

            # If syslog is available, go there by default
            if os.path.exists("/dev/log"):
                logger.propagate = False

                handler = logging.handlers.SysLogHandler(address='/dev/log')
                handler.ident = os.path.basename(sys.argv[0]) + " " # space required for syslog
                logger.addHandler(handler)

            self.logger = logger

        # Refers to the configuration that we want
        self.nic_configuration = []

        self.load_all_interfaces()

        # If the config file exists, load it
        if self.config != None:
            self.import_configuration()


    def load_all_interfaces(self):
        netlink = IPRoute()
        raw_ifaces = netlink.get_links()

        # Create a basic interface for each item
        for raw_iface in raw_ifaces:
            self.nic_configuration.append(
                InterfaceConfiguration(
                    self.logger,
                    raw_iface.get_attr('IFLA_IFNAME'),
                    raw_iface.get_attr('IFLA_ADDRESS')
                )
            )

        # We're done with netlink in this context
        netlink.close()

        # Now load all the data from the kernel
        self.refresh_all()


    def refresh_all(self):
        '''Refreshs all network interfaces'''

        for interface in self.nic_configuration:
            interface.refresh()

    def print_interfaces(self):
        '''Dumps the network interfaces to stdout'''
        print("\n=== Linux Network Configuration ===")

        for interface in self.nic_configuration:
            print("\nInterface:", interface.current_name)
            print("State:", interface.state)
            print("MAC Address:", interface.mac_address)

            # Only print addresses if we have them
            if interface.state != 'DOWN':
                print("Addresses:")
                for addr in interface.current_ip_addresses:
                    print("  ", addr.ip_addr)

            if interface.managed is True:
                print("Interface is configured. Settings applied at commit:")
                if interface.current_name != interface.name:
                    print("  Rename to:", interface.name)
            else:
                print("Interface is NOT configured for NDR")

    def get_all_managed_interfaces(self):
        '''Returns a list of all managed interfaces'''

        managed_interfaces = []
        for interface in self.nic_configuration:
            if interface.managed is True:
                managed_interfaces.append(interface)

        return managed_interfaces

    def get_nic_config_by_mac_address(self, mac_address):
        '''Retrieves the NIC configuration based on MAC address,

        If it's not found, its created automatically'''

        for interface in self.nic_configuration:
            if interface.mac_address == mac_address:
                return interface

        raise ValueError("Interface not found")

    def get_nic_config_by_name(self, name):
        '''Retrieves the NIC configuration by interface name.abs

        If its not found, an error is raised as this should only be used for managed
        interfaces'''

        for interface in self.nic_configuration:
            if interface.name == name:
                return interface

        raise ValueError("Interface not found")

    def set_configuration_method(self, interface, method):
        '''Configures how an interface is configured'''

        interface = self.get_nic_config_by_name(interface)
        interface.method = method

    def add_static_addr(self, interface, address, prefixlen):
        '''Add an address to an interface. Static configuration only'''
        interface = self.get_nic_config_by_name(interface)
        interface.add_static_addr(address, prefixlen)

    def rename_interface(self, old_name, new_name):
        '''Updates the configuration dict to the interface name'''

        interface = self.get_nic_config_by_name(old_name)
        interface.managed = True
        interface.name = new_name

    def apply_configuration(self, oneshot=False):
        '''Applies the configuration from the network dict'''
        for nic in self.nic_configuration:
            if nic.managed == True:
                nic.apply_configuration()

    def to_yaml(self):
        '''Exports configuration information as a YAML file'''
        cfg_dict = {}
        interface_dicts = []

        for interface in self.nic_configuration:
            if interface.managed is True:
                interface_dicts.append(
                    interface.to_dict()
                )

        cfg_dict['interfaces'] = interface_dicts

        return yaml.dump(cfg_dict)

    def export_configuration(self):
        '''Exports configuration information revelant to restore state'''
        with open(self.config, 'w') as f:
            f.write(self.to_yaml())

    def import_configuration(self):
        with open(self.config, 'r') as f:
            nic_dicts = yaml.safe_load(f.read())

        if nic_dicts is not None:
            if "interfaces" in nic_dicts:
                managed_nics = nic_dicts['interfaces']

                # For each NIC we have the configuration for, load it, then configure it.
                for nic in managed_nics:
                    # See if we can find this NIC
                    actual_nic = self.get_nic_config_by_mac_address(nic['mac_address'])
                    actual_nic.from_dict(nic)

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
