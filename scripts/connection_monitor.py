#!/usr/bin/env python

import socket
from struct import unpack
import pcapy
import sys
import argparse
import time


class ArgParser(object):
    '''
    Simple Argument-Parser class
    '''
    def __init__(self):
        '''
        Init the Parser
        '''
        self.main_parser = argparse.ArgumentParser()
        self.add_args()

    def add_args(self):
        '''
        Add new arguments
        '''

        self.main_parser.add_argument('-i',
                                      type=str,
                                      default='eth0',
                                      dest='iface',
                                      required=False,
                                      help=('the interface to dump the'
                                            'master runs on(default:eth0)'))

        self.main_parser.add_argument('-n',
                                      type=int,
                                      default=5,
                                      dest='ival',
                                      required=False,
                                      help=('interval for printing stats '
                                            '(default:5)'))

        self.main_parser.add_argument('-I',
                                      type=bool,
                                      default=False,
                                      const=True,
                                      nargs='?',
                                      dest='only_ip',
                                      required=False,
                                      help=('print unique IPs making new '
                                            'connections with SYN set'))

    def parse_args(self):
        '''
        parses and returns the given arguments in a namespace object
        '''
        return self.main_parser.parse_args()


class PCAPParser(object):
    '''
    parses a network packet on given device and
    returns source, target, source_port and dest_port
    '''

    def __init__(self, iface):
        self.iface = iface

    def run(self):
        '''
        main loop for the packet-parser
        '''
        # open device
        # Arguments here are:
        #   device
        #   snaplen (maximum number of bytes to capture _per_packet_)
        #   promiscious mode (1 for true)
        #   timeout (in milliseconds)
        cap = pcapy.open_live(self.iface, 65536, 1, 0)

        count = 0
        l_time = None

        while 1:

            packet_data = {
                           'ip': {},
                           'tcp': {}
                          }

            (header, packet) = cap.next()

            eth_length, eth_protocol = self.parse_ether(packet)

            # Parse IP packets, IP Protocol number = 8
            if eth_protocol == 8:
                #Parse IP header
                #take first 20 characters for the ip header
                version_ihl, version, ihl, iph_length, ttl, protocol, s_addr, d_addr = self.parse_ip(packet, eth_length)
                packet_data['ip']['s_addr'] = s_addr
                packet_data['ip']['d_addr'] = d_addr

                #TCP protocol
                if protocol == 6:

                    source_port, dest_port, flags, data = self.parse_tcp(packet, iph_length, eth_length)
                    packet_data['tcp']['d_port'] = dest_port
                    packet_data['tcp']['s_port'] = source_port
                    packet_data['tcp']['flags'] = flags
                    packet_data['tcp']['data'] = data
                    yield packet_data

    def parse_ether(self, packet):
        '''
        parse ethernet_header and return size and protocol
        '''
        eth_length = 14

        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])
        return eth_length, eth_protocol

    def parse_ip(self, packet, eth_length):
        '''
        parse ip_header and return all ip data fields
        '''
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]

        #now unpack them:)
        iph = unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        return [version_ihl,
                version,
                ihl,
                iph_length,
                ttl,
                protocol,
                s_addr,
                d_addr]

    def parse_tcp(self, packet, iph_length, eth_length):
        '''
        parse tcp_data and return source_port,
        dest_port and actual packet data
        '''
        p_len = iph_length + eth_length
        tcp_header = packet[p_len:p_len+20]

        #now unpack them:)
        tcph = unpack('!H HLLBBHHH', tcp_header)
        #  H     H     L   L   B   B      H   H   H
        #  2b    2b    4b  4b  1b  1b     2b  2b  2b
        #  sport dport seq ack res flags  win chk up
        # (22,   36513, 3701969065, 2346113113, 128, 24, 330, 33745, 0)
        source_port = tcph[0]

        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4
        tcp_flags = tcph[5]

        h_size = eth_length + iph_length + tcph_length * 4
        data_size = len(packet) - h_size

        data = packet[h_size:]

        return source_port, dest_port, tcp_flags, data


class SaltNetstat(object):
    '''
    Reads /proc/net/tcp and returns all connections
    '''

    def proc_tcp(self):
        '''
        Read the table of tcp connections & remove header
        '''
        with open('/proc/net/tcp', 'r') as tcp_f:
            content = tcp_f.readlines()
            content.pop(0)
        return content

    def hex2dec(self, hex_s):
        '''
        convert hex to dezimal
        '''
        return str(int(hex_s, 16))

    def ip(self, hex_s):
        '''
        convert into readable ip
        '''
        ip = [(self.hex2dec(hex_s[6:8])),
              (self.hex2dec(hex_s[4:6])),
              (self.hex2dec(hex_s[2:4])),
              (self.hex2dec(hex_s[0:2]))]
        return '.'.join(ip)

    def remove_empty(self, array):
        '''
        create new list without empty entries
        '''
        return [x for x in array if x != '']

    def convert_ip_port(self, array):
        '''
        hex_ip:hex_port to str_ip:str_port
        '''
        host, port = array.split(':')
        return self.ip(host), self.hex2dec(port)

    def run(self):
        '''
        main loop for netstat
        '''
        while 1:
            ips = {
                    'ips': {}
                  }
            content = self.proc_tcp()

            for line in content:
                line_array = self.remove_empty(line.split(' '))
                l_host, l_port = self.convert_ip_port(line_array[1])
                r_host, r_port = self.convert_ip_port(line_array[2])
                if l_port == '80':
                    if r_host not in ips['ips']:
                        ips['ips'][r_host] = 0
                    ips['ips'][r_host] += 1

            yield (len(ips['ips']))
            time.sleep(0.5)


def filter_new_cons(packet):
    '''
    filter packets by there tcp-state and
    returns codes for specific states
    '''
    flags = []
    TCP_FIN = 0x01
    TCP_SYN = 0x02
    TCP_RST = 0x04
    TCP_PSH = 0x08
    TCP_ACK = 0x10
    TCP_URG = 0x20
    TCP_ECE = 0x40
    TCP_CWK = 0x80

    if packet['tcp']['flags'] & TCP_FIN:
        flags.append('FIN')
    elif packet['tcp']['flags'] & TCP_SYN:
        flags.append('SYN')
    elif packet['tcp']['flags'] & TCP_RST:
        flags.append('RST')
    elif packet['tcp']['flags'] & TCP_PSH:
        flags.append('PSH')
    elif packet['tcp']['flags'] & TCP_ACK:
        flags.append('ACK')
    elif packet['tcp']['flags'] & TCP_URG:
        flags.append('URG')
    elif packet['tcp']['flags'] & TCP_ECE:
        flags.append('ECE')
    elif packet['tcp']['flags'] & TCP_CWK:
        flags.append('CWK')
    else:
        print "UNKNOWN PACKET"

    if packet['tcp']['d_port'] == 80:
        # track new connections
        if 'SYN' in flags and len(flags) == 1:
            return 10
        # track closing connections
        elif 'FIN' in flags:
            return 12

    # packet does not match requirements
    else:
        return None


def main():
    '''
    main loop for whole script
    '''
    # passed parameters
    args = vars(ArgParser().parse_args())

    # reference timer for printing in intervals
    r_time = 0

    # the ports we want to monitor
    ports = [80]

    print "Sniffing device {0}".format(args['iface'])

    stat = {
              'new': 0,
              'est': 0,
              'fin': 0,
              'ips': 0,
            }

    if args['only_ip']:
        print (
               'IPs making new connections '
               '(ports:{0}, interval:{1})'.format(ports,
                                                  args['ival'])
              )
    else:
        print (
               'Network Status '
               '(ports:{0}, interval:{1})'.format(ports,
                                                  args['ival'])
              )
    try:
        while 1:
            s_time = int(time.time())

            packet = PCAPParser(args['iface']).run().next()

            p_state = filter_new_cons(packet)

            ips = []

            # new connection to 
            if p_state == 10:
                stat['new'] += 1
                if packet['ip']['s_addr'] not in ips:
                    ips.append(packet['ip']['s_addr'])
            # closing connection to 4505
            elif p_state == 12:
                stat['fin'] += 1


            # get the established connections to 80
            # these would only show up in tcpdump if data is transferred
            # but then with different flags (PSH, etc.)
            stat['est'] = SaltNetstat().run().next()

            # print only in intervals
            if (s_time % args['ival']) == 0:
                # prevent printing within the same second
                if r_time != s_time:
                    if args['only_ip']:
                        msg = 'IPs/80: {0}'.format(len(ips))
                    else:
                        msg = "80 =>[ est: {0}, ".format(stat['est'])
                        msg += "new: {0}/s, ".format(stat['new'] / args['ival'])
                        msg += "fin: {0}/s ] ".format(stat['fin'] / args['ival'])

                    print msg

                    # reset the so far collected stats
                    for item in stat:
                        stat[item] = 0
                    r_time = s_time

    except KeyboardInterrupt:
        sys.exit(1)

if __name__ == "__main__":
    main()
