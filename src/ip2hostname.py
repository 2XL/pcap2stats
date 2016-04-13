import socket

import dns.reversename as dnsre
import dns.resolver
ip = "162.125.32.129"

socket.gethostbyaddr(ip)


# conver ip address from dns reverse map names



n = dnsre.from_address(ip)
print n
print dnsre.to_address(n)

# print dns.resolver.query("129.32.125.162.in-addr.arpa", "PTR")





