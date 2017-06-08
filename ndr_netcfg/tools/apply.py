#!/usr/bin/python3
# This file is part of NDR.
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

import os

import argparse
import ndr_netcfg

def main():
    '''Applies the network configuration saved in a config file'''
    parser = argparse.ArgumentParser(
        description="Interactively reconfigures the network interfaces for NDR")
    parser.add_argument('-c', '--config',
                        default='/persistant/etc/ndr/network_config.yml',
                        help='Network Configuration File')
    parser.add_argument('--oneshot',
                        action='store_true',
                        help='Only configures the network once, instead of running helper daemons')
    args = parser.parse_args()

    if os.getuid() != 0:
        print("ERROR: must be run as root")
        return

    net_config = ndr_netcfg.NetworkConfiguration(args.config)
    net_config.apply_configuration(oneshot=args.oneshot)

if __name__ == "__main__":
    main()
