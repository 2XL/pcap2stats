import pcapy
from impacket.ImpactDecoder import EthDecoder
# import pcapparser
import netifaces as ni
from impacket.ImpactPacket import IP, TCP, UDP, ICMP
import dpkt
import json
# list all the network devices
pcapy.findalldevs()
decoder = EthDecoder()
max_bytes = 1024
promiscuous = False # not capture all the network traffice only the trafice toward current host
read_timeout = 100 # in milliseconds
iface = 'eth0'
# pc = pcapy.open_live("name of network device to capture from", max_bytes, promiscuous, read_timeout)
pc = pcapy.open_live("eth0", max_bytes, promiscuous, read_timeout)

ip = ni.ifaddresses(iface)[2][0]['addr']
stacksync_ip = "10.30.235.91"
owncloud_ip = "10.30.232.183"
ips = [ip, stacksync_ip, owncloud_ip]
p = ["80", "443", "8080", "3128", "38088", "5672"]                      # ports
my_filter = "(port " + " || port ".join(p) + ") && (host " + " || host ".join(ips) + ")"   # filter
# (port 80 || port 443 || port 8080 || port 3128 || port 38088 || port 5672) && (host 10.30.236.141 || host 10.30.235.91 || host 10.30.232.183)


print my_filter
# pc.setfilter('tcp')
pc.setfilter(my_filter)

# callback for received packets
packet_index = 0
def on_recv_pkts(hdr, data):
    # packet_index += 1
    # print dir(hdr)
    print "time: {} lenght: {} lenght: {}".format(hdr.getts(), hdr.getcaplen(), hdr.getlen())
    print "<------"
    packet = decoder.decode(data)
    child = packet.child()
    print dir(child)
    if isinstance(child, IP):
        # print dir(child)
        child = child.child()
        #print dir(child)
        '''
        if isinstance(child, TCP):
            # if child.get_th_dport() == 993:
            print child.get_th_dport()
            # print 'IMAP'
            print dir(child)
            print child.get_data_as_string()
            print child.get_buffer_as_string()
            print child.get_bytes()
        if isinstance(child, UDP):
        '''
    print "------>"
    # print




packet_limit = -1                   # infinite
pc.loop(packet_limit, on_recv_pkts)    # capture packets