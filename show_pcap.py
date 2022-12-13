import dpkt
import socket
from dpkt.compat import compat_ord

def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)

def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

with open('33.pcap', 'rb') as fr:
    reader = dpkt.pcap.Reader(fr)
    for ts, pkt in reader.readpkts():
        # print(ts, pkt)
        print(len(pkt))
        
        eth = dpkt.ethernet.Ethernet(pkt)
        print("%#02X"% eth.type)
        
        # print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)
        # print(eth.pack_hdr)

                # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data
        # print(ip.df)
        # # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        # do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        # more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        # fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
        # print("version = %d" %ip.v)
        # print("ip header len = %d" %(ip.hl*32/8))
        # print("tos = %d" %ip.tos)
        # print("precedence = %d" %(ip.tos & 0xe))
        # print("id = %d" %ip.id)
        # print("flags %#02x"%(ip.off >>8))
        # # print("proto ", ip.get_proto(IP_PROTO_IP))
        print('protocol %d(%s)'%(ip.p, ip.__class__.__name__))
        # print('checksum = %0#X' %ip.sum)
        # # Print out the info
        # print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
        #       (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))

        # TCP
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            print("d port = %d" % tcp.sport)
            print('sequence =%ld' % tcp.seq)
            print('offset =%d' % (tcp.off*32/8))
            print('flag = %#X' % tcp.flags)
            print('window = %d' %tcp.win)
            print('checksum = %#X' %tcp.sum)
            print('urgent point = %d' %tcp.urp)

        # UDP
        if isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            print('source port = %d' % udp.sport)
            print('des port = %d' % udp.dport)
            print('udp len = %d '% udp.ulen)
        
        # ICMP
        if isinstance(ip.data, dpkt.icmp.ICMP):
            icmp = ip.data
            print('type = %d ' %icmp.type)