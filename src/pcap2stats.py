#!/usr/bin/python

import netifaces
import pcapy
import sys

print "Packet Sniffer..."


def main(argv):

    devices = pcapy.findalldevs()
    print devices
    # ['eth0', 'wlan0', 'nflog', 'nfqueue', 'any', 'lo']

if __name__ == "__main__":
    main(sys.argv)