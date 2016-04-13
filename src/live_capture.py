import os, json, pcapy, socket
from impacket.ImpactDecoder import EthDecoder
import netifaces as ni
import pprint
from impacket.ImpactPacket import IP, TCP, UDP, ICMP
import DNS

if os.getuid() == 0:
    print("r00tness!")
else:
    print("I cannot run as a mortal. Sorry.")





global packet_index, prot_dict, type_dict, flow_dict, host_cache
packet_index = 0

type_dict = {}      # type of layer one => IP, ARP...
prot_dict = {}      # type of layer two => TCP, UDP

# size_dict = {"hit": 0, "size": 0}      # size_dict[source] = [counter, size]

flow_dict = {}     # traffic flow [src-host, dst-host] = #
host_cache = {}    # caching resolved ip to hostname

#

def getHostnameByIp(ip):
    global host_cache
    if ip in host_cache:
        hostname = host_cache[ip]
    else:  # cache it
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            print ip
            host_cache[ip] = ip  # cannot be resolved, avoid resolving it again
            return ip
        host_cache[ip] = hostname
    return hostname


def getHostFlowByIps(src_host, dst_host, size):
    global flow_dict
    key = "{}_{}".format(src_host, dst_host)
    if key in flow_dict:
        flow_dict[key]['hit'] += 1
        flow_dict[key]['size'] += size
    else:
        flow_dict[key] = {"hit": 0, "size": 0}




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
manager_ip = "10.30.236.141"


ips = [ip]  # , stacksync_ip, owncloud_ip]
p = ["80", "53", "443", "8080", "3128", "38088", "5672"]                      # ports


# my_filter = "(port " + " || port ".join(p) + ") && (host " + " || host ".join(ips) + ")"   # filter
my_filter = "(host " + " || host ".join(ips) + ")"   # filter
# my_filter = "(port " + " || port ".join(p) + ") && (host " + " || host ".join(ips) + ") && (host not "+manager_ip+")"   # filter
# (port 80 || port 443 || port 8080 || port 3128 || port 38088 || port 5672) && (host 10.30.236.141 || host 10.30.235.91 || host 10.30.232.183)


print my_filter
pc.setfilter(my_filter)

# callback for received packets




def on_recv_pkts(hdr, data):
    global packet_index
    global type_dict, prot_dict

    packet_index += 1
    # print dir(hdr)
    print "<------"
    print "{} getts: {} getcaplen: {} getlen: {}".format(packet_index, hdr.getts(), hdr.getcaplen(), hdr.getlen())
    # getcaplen : Number of bytes actually captured.
    # getlen : Number of original bytes in the packet.
    ether_packet = decoder.decode(data)

    # print ether_packet.get_ether_type()
    print ether_packet.get_size()
    # print ether_packet.get_ether_dhost()
    # print ether_packet.get_ether_shost()  # decimal mac address

    # IP
    packet_type = ether_packet.child()
    # print ether_packet.get_ip_address()
    print packet_type.__class__.__name__
    if packet_type.__class__.__name__ in type_dict:
        type_dict[packet_type.__class__.__name__] += 1
    else:
        type_dict[packet_type.__class__.__name__] = 0

    if packet_type.__class__.__name__ == "ARP":
        print packet_type
        return None

    dst_host = getHostnameByIp(packet_type.get_ip_dst())
    src_host = getHostnameByIp(packet_type.get_ip_src())
    print "{}~>>~{}".format(src_host, dst_host)
    print "get_header_size: {}".format(packet_type.get_header_size())  # ip header size, always 20 bytes
    print "get_size: {}".format(packet_type.get_size())

    # print packet_type.get_bytes()  # data in bytes
    # print packet_type.get_data_as_string()

    # print "get_ip_df: {}".format(packet_type.get_ip_df())
    # print "get_ip_dst: {}".format(packet_type.get_ip_dst())

    # print "get_ip_hl: {}".format(packet_type.get_ip_hl())  # internet header length
    # print "get_ip_id: {}".format(packet_type.get_ip_id())  # identification
    # print "get_ip_len: {}".format(packet_type.get_ip_len())  # total length
    # print "get_ip_mf: {}".format(packet_type.get_ip_mf())
    # print "get_ip_off: {}".format(packet_type.get_ip_off())
    # print "get_ip_offmask: {}".format(packet_type.get_ip_offmask())
    # print "get_ip_p: {}".format(packet_type.get_ip_p())  # padding
    # print "get_ip_rf: {}".format(packet_type.get_ip_rf())
    # print "get_ip_src: {}".format(packet_type.get_ip_src())

    # print "get_ip_sum: {}".format(packet_type.get_ip_sum()) # header checksum
    # print "get_ip_tos: {}".format(packet_type.get_ip_tos()) # Type of service
    # print "get_ip_ttl: {}".format(packet_type.get_ip_ttl()) # time to live
    # print "get_ip_v: {}".format(packet_type.get_ip_v())
    # print "get_pseudo_header: {}".format(packet_type.get_pseudo_header())

    getHostFlowByIps(src_host, dst_host, ether_packet.get_size())

    #######################################################################
    # TCP OR UDP
    packet_protocol = packet_type.child()
    packet_protocol_type = packet_protocol.__class__.__name__
    if packet_protocol_type in prot_dict:
        prot_dict[packet_protocol_type] += 1
    else:
        prot_dict[packet_protocol_type] = 0

    ##

    if packet_protocol_type == "TCP": # layer 4 of the OSI model
        print "--> tcp"

        '''
        'get_ACK'
        'get_CWR'
        'get_ECE'
        'get_FIN'
        'get_PSH'
        'get_RST'
        'get_SYN'
        'get_URG'
        'get_buffer_as_string'
        'get_byte'
        'get_bytes'
        'get_data_as_string'
        'get_flag'
        'get_header_size'
        'get_ip_address'
        'get_long'
        'get_long_long'
        'get_options'
        'get_packet'
        'get_padded_options'
        'get_pseudo_header'
        'get_size'
        'get_th_ack'
        'get_th_dport'
        'get_th_flags'
        'get_th_off'
        'get_th_reserved'
        'get_th_seq'
        'get_th_sport'
        'get_th_sum'
        'get_th_urp'
        'get_th_win'
        '''
        # print "get_ACK: {}".format( packet_protocol.get_ACK()) # indicates that this segment is carrying an aknowledgment # data received ACKnowledg
        # print "get_CWR: {}".format( packet_protocol.get_CWR()) # congestion window reduced
        # print "get_ECE: {}".format( packet_protocol.get_ECE()) # echo # congestion notification feature (sender and receiver need to support it)
        # print "get_FIN: {}".format( packet_protocol.get_FIN()) # finish, request the connection to be closed # close a connection
        # print "get_PSH: {}".format( packet_protocol.get_PSH()) # the sender is using : tcp push feature, # send inmediately (streaming delay), rcv push inmediately
        # print "get_RST: {}".format( packet_protocol.get_RST()) # reset bit: the sender has encountered a problem and wants to reset the connection
        # print "get_SYN: {}".format( packet_protocol.get_SYN()) # request to synchronize sequence numbers and establish a connection # init a connection
        # print "get_URG: {}".format( packet_protocol.get_URG()) # certain data within a segment is urgent and should be priorized
        # print "get_buffer_as_string: {}".format( packet_protocol.get_buffer_as_string())
        print "get_header_size: {}".format(packet_protocol.get_header_size())
        # print "get_options: {}".format( packet_protocol.get_options())
        # print "get_padded_options: {}".format( packet_protocol.get_padded_options()) # ensure the tcp header ends and begins on a 32 bit boundary [by zeros]
        print "get_size: {}".format( packet_protocol.get_size())
        # # print "get_th_ack: {}".format( packet_protocol.get_th_ack()) # 32bit number the sender is expecting to receive
        #
        # # th => transmission header
        # print "get_th_flags: {}".format( packet_protocol.get_th_flags())
        # print "get_th_off: {}".format( packet_protocol.get_th_off())
        # print "get_th_reserved: {}".format( packet_protocol.get_th_reserved()) # future use
        # print "get_th_seq: {}".format( packet_protocol.get_th_seq())
        #
        # print "get_th_sum: {}".format( packet_protocol.get_th_sum())
        # print "get_th_urp: {}".format( packet_protocol.get_th_urp())
        # print "get_th_win: {}".format( packet_protocol.get_th_win())

        print "get_th_dport: {}".format( packet_protocol.get_th_dport())
        print "get_th_sport: {}".format( packet_protocol.get_th_sport())



    elif packet_protocol_type == "UDP":
        print "--> udp"

        '''
        'get_buffer_as_string'
        'get_byte'
        'get_bytes'
        'get_data_as_string'
        'get_header_size'
        'get_ip_address'
        'get_long'
        'get_long_long'
        'get_packet'
        'get_pseudo_header'
        'get_size'
        'get_uh_dport'
        'get_uh_sport'
        'get_uh_sum'
        'get_uh_ulen'
        'get_word'
        '''
        # print "protocol: {}".format(packet_protocol.protocol) # 17 => RFC768 : UDP
        # print "ethertype: {}".format( packet_protocol.ethertype)

        # print packet_protocol.get_data_as_string()
        print "get_header_size: {}".format( packet_protocol.get_header_size()) # always 8 bytes
        # print packet_protocol.get_packet()
        print "get_size: {}".format( packet_protocol.get_size())

        print "get_uh_dport: {}".format( packet_protocol.get_uh_dport())                # todo:  dest port
        print "get_uh_sport: {}".format( packet_protocol.get_uh_sport())                # todo:  source port
        # print "get_uh_sum: {}".format( packet_protocol.get_uh_sum())
        # print "get_uh_ulen: {}".format( packet_protocol.get_uh_ulen())
        # print packet_protocol.packet_printable



    else:
        print "Unhandled protocol {}".format(packet_protocol_type)
    # information = packet_protocol.child()  # information
    # print "information withing the packet"
    # print information
    # print "information end"
    print "-> "
    print host_cache
    print flow_dict








packet_limit = -1                   # infinite
pc.loop(packet_limit, on_recv_pkts)    # capture packets