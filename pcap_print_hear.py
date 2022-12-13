# -*- coding: UTF-8 -*-
#!/usr/bin/env python3

import argparse
import dpkt

def cmd_line_args():
    parser = argparse.ArgumentParser(description='pktsniffer surpport analyses ether、ip、tcp、udp、icmp header.')
    parser.add_argument('-r', nargs='+', metavar='<input pcap file>',
        help='read pcap file to analyses', required=True)
    parser.add_argument('-c', nargs='+', required=False, help='limit to output packets number.')
    #parser.add_argument('filter', type=str, nargs='+', help='display by host or/and port, ip, tcp, udp,icmp')
    #parser.add_argument('-net', help='display all ip(a.b.c.d) address mask last ip digital(a.b.c.x).')
    # parser.add_argument('host', help='display math the ip address.')
    # parser.add_argument('port', help='display tcp/udp ports.')
    # parser.add_argument('ip', help='display ip header.')
    # parser.add_argument('tcp', help='display tcp header.')
    # parser.add_argument('udp', help='display udp header.')
    # parser.add_argument('icmp', help='display icmp header.')
    
    args = parser.parse_args()
    return args

def check_option(args):
    print(args)

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
            print(filters)
    else:
        print("only support one condition expression.")
    
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


def print_packet_detail(args, packet):
    pass

def print_ether_header(packet):
    print("ETHER: ----- Ether Header -----")
    print("ETHER:")

    print("ETHER: Packet size = %d bytes" %)
    print("ETHER: Destination = %s" %)
    print("ETHER: Source = %s" %)
    print("ETHER: EtherType = %s"%)
    print("ETHER:")
    
    

def print_ip_header(packet):
    print("IP: ----- IP Header -----")
    print("IP:")
    print("IP: Version = %d" %)
    print("IP: Header length = %d bytes" %)
    print("IP: Type of service = %#x" % )
    print("IP:      xxx. .... = %d (%s)")
    print("IP:      ...%d .... = %s")
    print("IP:      .... %d... = %s")
    print("IP:      .... .%d.. = %s")
    print("IP: Total length = %d bytes")
    print("IP: Identification = %d")
    print("IP: Flags = %#x")
    print("IP: .%d.. ....= %s")
    print("IP: ..%d. ....= %s")
    print("IP: Fragment offset = %d bytes"%)
    print("IP: Time to live = %d secodes/hops"%)
    print("IP: Protocol = %d (%s)"%)
    print("IP: Header checksum = %#x"%)
    print("IP: Source address = %s"%)
    print("IP: Destination address = %s"%)
    print("IP: No options")
    print("IP:")

    pass

def print_tcp_header(packet):
    print("TCP: ----- TCP Header -----")
    print("TCP:")
    print("TCP: Source port = %d"%)
    print("TCP: Destination poart = %d"%)
    print("TCP: Sequence number = %ld"%)
    print("TCP: Acknowledgement number = %ld"%)
    print("TCP: Data offset = %d bytes"%)
    print("TCP: Flags = %#x"%)
    print("TCP:     ..%d. ....= %s"%)
    print("TCP:     ...%d ....=%s"%)
    print("TCP:     .... %d...=%s"%)
    print("TCP:     .... ..%d.=%s"%)
    print("TCP:     .... ...%d=%s"%)
    print("TCP: Window = %d"%)
    print("TCP: Checksum = %#x"%)
    print("TCP: Urgent pointer = %d"%)
    print("TCP: No options"%)
    print("TCP:")

def print_udp_header(packet):
    print("UDP: ----- UDP Header -----")
    print("UDP:")
    print("UDP: Source port = %d"%)
    print("UDP: Destination port = %d"%)
    print("UDP: Length = %d"%)
    print("UDP: Checksum = %#x"%)
    print("UDP:")

def print_icmp_header(packet):
    print("ICMP: ----- ICMP Header -----")
    print("ICMP:")
    print("ICMP: Type = %d (%s)"%)
    print("ICMP: Code = %d"%)
    print("ICMP: Checksum = %#x"%)
    print("ICMP:")

def display_packet(args):

    if args.get('host') != None:
        if args.get('host') == 'x.x.x.x':
            print_packet_detail(xxx)
    else:
        print_packet_detail(xxx)


def main():
    args = cmd_line_args()
    filters = check_option(args)
    print('filters =  ', filters)


    
if __name__ == '__main__':
    main()