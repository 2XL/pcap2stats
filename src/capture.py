#!/usr/bin/python
# -*- coding: iso-8859-1 -*-

from threading import Thread
import netifaces as ni
import time, traceback, sys
import pcapy

#-------------------------------------------------------------------------------
# Thread to capture the packets
#-------------------------------------------------------------------------------
class pcap_capture(Thread):


    def __init__(self, iface, pcap_name):
        Thread.__init__(self)
        #TODO: Parameters!
        #print ni.ifaddresses("eth0")[2]
        #print ni.ifaddresses("eth1")[2]
        '''
        {17: [{'broadcast': 'ff:ff:ff:ff:ff:ff', 'addr': '00:90:f5:d7:14:27'}], 2: [{'broadcast': '10.30.255.255', 'netmask': '255.255.0.0', 'addr': '10.30.236.141'}], 10: [{'netmask': 'ffff:ffff:ffff:ffff::', 'addr': 'fe80::290:f5ff:fed7:1427%eth0'}]}
        [{'broadcast': '10.30.255.255', 'netmask': '255.255.0.0', 'addr': '10.30.236.141'}]
        {'broadcast': '10.30.255.255', 'netmask': '255.255.0.0', 'addr': '10.30.236.141'}
        '10.30.236.141'
        '''

        ip = ni.ifaddresses(iface)[2][0]['addr']
        p = ["80", "443", "8080", "3128", "38088", "5672"]                      # ports
        my_filter = "(port " + " || port ".join(p) + ") && (host " + ip + ")"   # filter

        print my_filter

        self.stopit = False
        self.done = False
        self.bytes = 0
        self.packets = 0

        max_bytes = 1600
        promiscuous = 1
        read_timeout = 100
        self.pcap = pcapy.open_live(iface, max_bytes , promiscuous , read_timeout)
        #http://snipplr.com/view/3579/
        #pc = pcapy.open_live("name of network device to capture from", max_bytes, promiscuous, read_timeout)

        self.pcap.setfilter(my_filter)
        self.dumper = self.pcap.dump_open(pcap_name)  # output dump file

    def stop_flag(self):
        return self.stopit

    def get_bytes(self):
        return self.bytes

    def get_packets(self):
        return self.packets

    def call_back(self, header, data):
        self.packets += 1
        self.bytes += header.getlen()
        self.dumper.dump(header, data)

    def capture(self):
        while not self.stopit:
            self.pcap.dispatch(1, self.call_back)
        self.done = True

    def run (self): # start capure
        self.capture()

    def stop(self):
        self.stopit = True
        while not self.done:
            pass  # matar el woker
        return self.done

#-------------------------------------------------------------------------------
# Main - For testing purposes
#-------------------------------------------------------------------------------
if __name__ == '__main__':

    # start capturing the traffic
    worker = None
    period = 10
    print sys.argv

    print len(sys.argv)
    # iface =
    if len(sys.argv) == 1:
        iface = "eth0"
    elif len(sys.argv) == 2:
        iface = sys.argv[1]
    elif len(sys.argv) == 3:
        iface = sys.argv[1]
        period = int(sys.argv[2])
    else:
        sys.exit()

    try:
        # p = "/tmp/test.pcap"
        p = "test.pcap"
        worker = pcap_capture(iface, p)
        worker.daemon = True
        worker.start()
        time.sleep(period)  # here goes a random sleep
        print "packets:", worker.get_packets(), "bytes:", worker.get_bytes()
    except:
        traceback.print_exc(file=sys.stderr)
    worker.stop()


