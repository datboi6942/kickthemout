#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# scan.py

"""
Copyright (C) 2017-18 Nikolaos Kamarinakis (nikolaskam@gmail.com) & David Schütz (xdavid@protonmail.com)
See License at nikolaskama.me (https://nikolaskama.me/kickthemoutproject)
"""

import nmap

# perform a network scan with nmap
def scanNetwork(network):
    returnlist = []
    nm = nmap.PortScanner()
    # Updated scan arguments to use a more general host discovery method
    a = nm.scan(hosts=network, arguments='-sn -T5')

    for k, v in a['scan'].items():
        if str(v['status']['state']) == 'up':
            try:
                ip_address = str(v['addresses']['ipv4'])
                mac_address = str(v['addresses']['mac'])
                # Initialize encryption as unknown by default
                encryption = 'Unknown'
                # Check if the script output contains encryption information
                if 'broadcast-wifi-info' in v.get('script', {}):
                    encryption_info = v['script']['broadcast-wifi-info']
                    if 'WPA2' in encryption_info:
                        encryption = 'WPA2'
                    elif 'WPA3' in encryption_info:
                        encryption = 'WPA3'
                    elif 'WPA' in encryption_info:
                        encryption = 'WPA'
                # Append IP, MAC, and encryption info to the return list
                returnlist.append([ip_address, mac_address, encryption])
            except KeyError:
                # Handle cases where expected keys are missing
                returnlist.append([ip_address, mac_address, encryption])

    return returnlist
