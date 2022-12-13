# -*- coding: UTF-8 -*-
#!/usr/bin/env python3

import argparse
import dpkt
import socket
from dpkt.compat import compat_ord
import warnings


def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def cmd_line_args():
    parser = argparse.ArgumentParser(
        description='pktsniffer surpport analyses ether、ip、tcp、udp、icmp header.')
    parser.add_argument('-r', nargs='+', metavar='<input pcap file>',
                        help='read pcap file to analyses', required=True)
    parser.add_argument('-c', nargs='+', required=False,
                        help='limit to output packets number.')
    # parser.add_argument('filter', type=str, nargs='+', help='display by host or/and port, ip, tcp, udp,icmp')
    # parser.add_argument('-net', help='display all ip(a.b.c.d) address mask last ip digital(a.b.c.x).')
    # parser.add_argument('host', help='display math the ip address.')
    # parser.add_argument('port', help='display tcp/udp ports.')
    # parser.add_argument('ip', help='display ip header.')
    # parser.add_argument('tcp', help='display tcp header.')
    # parser.add_argument('udp', help='display udp header.')
    # parser.add_argument('icmp', help='display icmp header.')

    args = parser.parse_args()
    return args


def check_option(args):
    # print(args)

    filters = {}
    filters_str = ''
    filters['r'] = args.r[0]
    if args.c != None:
        filters['c'] = args.c[0]
        filters_str = args.c[1:]
    else:
        filters_str = args.r[1:]

    if len(filters_str) == 1:
        filters[filters_str[0]] = True
    elif len(filters_str) == 2:
        filters[filters_str[0]] = filters_str[1]
        # print(filters)
    else:
        # print("only support one condition expression.")
        pass

    print_all = True
    if 'ip' in filters:
        print_all = False

    if 'tcp' in filters:
        print_all = False

    if 'udp' in filters:
        print_all == False

    if 'icmp' in filters:
        print_all == False

    filters['all'] = print_all
    return filters


def get_tcp_udp_port(pkt):
    eth = dpkt.ethernet.Ethernet(pkt)
    if not isinstance(eth.data, dpkt.ip.IP):
        print('Non IP Packet type not supported %s\n' %
              eth.data.__class__.__name__)
        return None

    ip = eth.data

    if not isinstance(eth.data, dpkt.ip.IP):
        print('Non IP Packet type not supported %s\n' %
              eth.data.__class__.__name__)
        return None

    ip = eth.data
    #tcp or udp
    if ip.p == 6 or ip.p == 17:
        return (int(ip.data.sport), int(ip.data.dport))
    else:
        None


def print_packet_detail(args, pkt):
    if args.get('c') != None and args['pkt_filter_num'] >= int(args['c']):
        return

    # port_match = False
    if args.get('port') != None:
        tcp_udp_port = get_tcp_udp_port(pkt)
        # print("port ===> ", tcp_udp_port)
        if tcp_udp_port != None and (int(args['port']) == tcp_udp_port[0] or int(args['port']) == tcp_udp_port[1]):
            # print("MATCH")
            # port_match = True
            pass
        else:
            return

    ip_proto = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    eth = print_ether_header(pkt)
    ip = print_ip_header(eth, ip_proto)
    if ip != None:
        if ip_proto.get(ip.p) == "TCP":
            print_tcp_header(ip)
            args['pkt_filter_num'] = args['pkt_filter_num']+1
        elif ip_proto.get(ip.p) == "UDP":
            # if args.get('port') == None or (args.get('port') != None and (int(args.get('port')) == ip.data.sport or int(args.get('port')) == ip.data.dport)):
            print_udp_header(ip)
            args['pkt_filter_num'] = args['pkt_filter_num']+1
        elif ip_proto.get(ip.p) == "ICMP":
            print_icmp_header(ip)
            args['pkt_filter_num'] = args['pkt_filter_num']+1
        else:
            print('unknow protocol not support!')


def get_src_dst_IP(pkt):
    eth = dpkt.ethernet.Ethernet(pkt)
    if not isinstance(eth.data, dpkt.ip.IP):
        print('Non IP Packet type not supported %s\n' %
              eth.data.__class__.__name__)
        return None

    ip = eth.data
    return (inet_to_str(ip.src), inet_to_str(ip.dst))


def print_ether_header(pkt):
    print("ETHER: ----- Ether Header -----")
    print("ETHER:")

    print("ETHER: Packet size = %d bytes" % len(pkt))
    eth = dpkt.ethernet.Ethernet(pkt)
    print("ETHER: Destination = %s" % mac_addr(eth.dst))
    print("ETHER: Source = %s" % mac_addr(eth.src))
    print("ETHER: EtherType = %#02X (%s)" %
          (eth.type, eth.data.__class__.__name__))
    print("ETHER:")
    return eth


def print_ip_header(eth, proto):
    if not isinstance(eth.data, dpkt.ip.IP):
        print('Non IP Packet type not supported %s\n' %
              eth.data.__class__.__name__)
        return None

    ip = eth.data
    print("IP: ----- IP Header -----")
    print("IP:")
    print("IP: Version = %d" % ip.v)
    print("IP: Header length = %d bytes" % (ip.hl*32/8))
    print("IP: Type of service = %#x" % ip.tos)
    print("IP:      xxx. .... = %d (precedence)" % (ip.tos & 0xe))

    tos_b3 = ip.tos & 0x10
    if tos_b3 == 0:
        print("IP:      ...%d .... = %s" % (tos_b3, 'Normal Delay'))
    elif tos_b3 == 1:
        print("IP:      ...%d .... = %s" % (tos_b3, 'High Delay'))

    tos_b4 = ip.tos & 0x08
    if tos_b4 == 0:
        print("IP:      ...%d .... = %s" % (tos_b4, 'Normal Throughput'))
    elif tos_b4 == 1:
        print("IP:      ...%d .... = %s" % (tos_b4, 'High Throughput'))

    tos_b5 = ip.tos & 0x08
    if tos_b5 == 0:
        print("IP:      ...%d .... = %s" % (tos_b5, 'Normal reliability'))
    elif tos_b5 == 1:
        print("IP:      ...%d .... = %s" % (tos_b5, 'High reliability'))

    print("IP: Total length = %d bytes" % ip.len)
    print("IP: Identification = %d" % ip.id)
    print("IP: Flags = %#x" % (ip.off >> 8))

    print("IP: .%d.. ....= %s" % (ip.df, 'do not fragment'))
    print("IP: ..%d. ....= %s" % (ip.mf, 'more fragments'))
    print("IP: Fragment offset = %d bytes" % ip.offset)
    print("IP: Time to live = %d secodes/hops" % ip.ttl)
    print("IP: Protocol = %d (%s)" % (ip.p, proto.get(ip.p, 'unkown')))
    print("IP: Header checksum = %0#X" % ip.sum)
    print("IP: Source address = %s" % inet_to_str(ip.src))
    print("IP: Destination address = %s" % inet_to_str(ip.dst))
    print("IP: No options")
    print("IP:")
    return ip


def print_tcp_header(ip):
    if not isinstance(ip.data, dpkt.tcp.TCP):
        return

    tcp = ip.data

    print("TCP: ----- TCP Header -----")
    print("TCP:")
    print("TCP: Source port = %d" % tcp.sport)
    print("TCP: Destination poart = %d" % tcp.dport)
    print("TCP: Sequence number = %ld" % tcp.seq)
    print("TCP: Acknowledgement number = %ld" % tcp.ack)
    print("TCP: Data offset = %d bytes" % (tcp.off*32/8))
    print("TCP: Flags = %#x" % tcp.flags)

    flags_bit2 = tcp.flags & 0x20
    if flags_bit2 == 0:
        print("TCP:     ..%d. .... = Urgent: Not set" % flags_bit2)
    elif flags_bit2 == 1:
        print("TCP:     ..%d. .... = Urgent: set" % flags_bit2)

    flags_bit3 = tcp.flags & 0x10
    if flags_bit3 == 0:
        print("TCP:     ...%d .... = Acknowledgment: Not set" % flags_bit3)
    elif flags_bit3 == 1:
        print("TCP:     ...%d .... = Acknowledgment: set" % flags_bit3)

    flags_bit4 = tcp.flags & 0x08
    if flags_bit4 == 0:
        print("TCP:     .... %d... = Push Not set" % flags_bit4)
    elif flags_bit4 == 0:
        print("TCP:     .... %d... = Push set" % flags_bit4)

    flags_bit5 = tcp.flags & 0x04
    if flags_bit5 == 0:
        print("TCP:     .... .%d.. = Reset Not set" % flags_bit5)
    elif flags_bit5 == 0:
        print("TCP:     .... .%d.. = Reset set" % flags_bit5)

    flags_bit6 = tcp.flags & 0x02
    if flags_bit6 == 0:
        print("TCP:     .... ..%d. = Syn Not set" % flags_bit6)
    elif flags_bit6 == 0:
        print("TCP:     .... ..%d. = Syn set" % flags_bit6)

    flags_bit7 = tcp.flags & 0x01
    if flags_bit7 == 0:
        print("TCP:     .... ...%d = Fin Not set" % flags_bit7)
    elif flags_bit7 == 0:
        print("TCP:     .... ...%d = Fin set" % flags_bit7)

    print("TCP: Window = %d" % tcp.win)
    print("TCP: Checksum = %#x" % tcp.sum)
    print("TCP: Urgent pointer = %d" % tcp.urp)
    print("TCP: No options")
    print("TCP:")


def print_udp_header(ip):
    if not isinstance(ip.data, dpkt.udp.UDP):
        return

    udp = ip.data
    print("UDP: ----- UDP Header -----")
    print("UDP:")
    print("UDP: Source port = %d" % udp.sport)
    print("UDP: Destination port = %d " % udp.dport)
    print("UDP: Length = %d" % udp.ulen)
    print("UDP: Checksum = %#X" % udp.sum)
    print("UDP:")


def print_icmp_header(ip):
    if not isinstance(ip.data, dpkt.icmp.ICMP):
        return

    icmp = ip.data
    print("ICMP: ----- ICMP Header -----")
    print("ICMP:")
    print("ICMP: Type = %d " % (icmp.type))
    print("ICMP: Code = %d" % icmp.code)
    print("ICMP: Checksum = %#X" % icmp.sum)
    print("ICMP:")


def display_packet(filters):
    with open(filters['r'], 'rb') as fr:
        reader = dpkt.pcap.Reader(fr)
        for ts, pkt in reader.readpkts():
            ip_src_dst = get_src_dst_IP(pkt)
            if ip_src_dst != None:
                if filters.get('host') != None:
                    if filters.get('host') == ip_src_dst[0] or filters.get('host') == ip_src_dst[1]:
                        print_packet_detail(filters, pkt)
                else:
                    print_packet_detail(filters, pkt)


def main():
    warnings.filterwarnings("ignore")
    args = cmd_line_args()
    filters = check_option(args)
    filters['pkt_filter_num'] = 0
    # print('LOG ==> filters =  ', filters)
    display_packet(filters)


if __name__ == '__main__':
    main()
