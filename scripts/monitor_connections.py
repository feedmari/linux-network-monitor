#!/usr/bin/python   
#title           : monitor_connections.py
#description     : This program is used in order to monitor the network in real time.
#author          : Federico Marinelli
#bash_version    : 4.1.5(1)-release
#==============================================================================

'''
Parameters:

    <> connection_stat - Number of estabilished, new and closed connections at each time interval 
    <> proto type - Number of TCP, UDP, ICMP, TCP SYN packets
    <> packets_from_ip - Number of packets incoming, divided by ips
'''

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
                                      required=True,
                                      help=('interval for printing stats '
                                            '(default:5)'))

        self.main_parser.add_argument('-M',
                                      type=str,
                                      default='new_ips',
                                      dest='method',
                                      required=True,
                                      help=('Choose the method to use: \n connection_stat: Number of estabilished, new and closed connections every, \
                                        \n proto_type: TCP\s, UDP\s, ICMP\s\n ppip ,\n info ,\n bytes '))

        self.main_parser.add_argument('-a', \
            type=bool, default=False, dest='all_ports', help=('Monitor all the ports'))
       

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
                           'tcp': {},
                           'udp': {},
                           'icmp': {}
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
                    packet_data['type']='tcp'
                    source_port, dest_port, flags, data = self.parse_tcp(packet, iph_length, eth_length)
                    packet_data['tcp']['d_port'] = dest_port
                    packet_data['tcp']['s_port'] = source_port
                    packet_data['tcp']['flags'] = flags
                    packet_data['tcp']['data'] = data
                    yield packet_data

                #ICMP Packets
                elif protocol == 1 :
                    packet_data['type']='icmp'
                    u = iph_length + eth_length
                    icmph_length = 4
                    icmp_header = packet[u:u+4]

                    #now unpack them :)
                    icmph = unpack('!BBH' , icmp_header)
                     
                    icmp_type = icmph[0]
                    code = icmph[1]
                    checksum = icmph[2]

                    packet_data['icmp']['type']=str(icmp_type)
                    packet_data['icmp']['code']=str(code)        
                    h_size = eth_length + iph_length + icmph_length
                    data_size = len(packet) - h_size
                     
                    #get data from the packet
                    data = packet[h_size:]

                    packet_data['icmp']['data']=str(data)
                    yield packet_data 
                    

                #UDP packets
                elif protocol == 17 :
                    acket_data['type']='udp'
                    u = iph_length + eth_length
                    udph_length = 8
                    udp_header = packet[u:u+8]

                    #now unpack them :)
                    udph = unpack('!HHHH' , udp_header)
                     
                    source_port = udph[0]
                    dest_port = udph[1]
                    length = udph[2]
                    checksum = udph[3]
                    packet_data['udp']['d_port'] = str(dest_port)
                    packet_data['udp']['s_port'] = str(source_port)
                    packet_data['udp']['length'] = str(length)
                    h_size = eth_length + iph_length + udph_length
                    data_size = len(packet) - h_size
                     
                    #get data from the packet
                    data = packet[h_size:]
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

    # track new connections
    if 'SYN' in flags and len(flags) == 1:
        return 10
    # track closing connections
    elif 'FIN' in flags:
        return 12

def get_flag(packet):
    '''
    get TCP flag
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

    return flags



def main():
    '''
    main loop for whole script
    '''
    # passed parameters
    args = vars(ArgParser().parse_args())

    # reference timer for printing in intervals
    r_time = 0

    # do we want to monitor all the ports?
    ports = False

    print " [!] Sniffing device {0}".format(args['iface'])

    stat_type = {
                  'udp': 0,
                  'tcp': 0,
                  'icmp': 0
                }
    stat = {}
    ips = {}
    ips['addr_port'] = []
    ips['packet'] = []

    ips2 = {}
    ips2['addr_port'] = []
    ips2['packet'] = []

    ppip = {}

    if args['all_ports']:
        print (' [!] MONITORING ALL THE PORTS ')
        ports = True
    else:
        print (' [!] MONITORING PORT 80')

    if args['method'] == 'connection_stat':
        print ' [!] Showing number of estabilished, new and closed connections every '+ str(args['ival'])+' second'
    elif args['method'] == 'ppip':
        print ' [!] Showing Number of packets incoming, divided by source ip'
    elif args['method'] == 'proto_type':
        print ' [!] Showing number of TCP, UDP, ICMP, TCP SYN packets every '+ str(args['ival'])+' second'
    elif args['method'] == 'flag':
        print ' [!] [NOT IMPLEMENTED] Showing the number of packets divided by flags, arriving every '+ str(args['ival'])+' second'  
    else:
        print ' [ERROR] Method incorrect '
        sys.exit(1)      

    try:
        while 1:
            '''
            MONITORING THE FOLLOWING:
            connection_stat - Number of estabilished, new and closed connections at each time interval 
            proto type - Number of TCP, UDP, ICMP, TCP SYN packets
            packets_from_ip - Number of packets incoming, divided by ips
            
            info - print informations about the packets that pass through the node
            bytes - print the number of bytes of each packet trasmitted

            '''
            s_time = int(time.time())

            packet = PCAPParser(args['iface']).run().next()

            #--------------------------------------------------------------------#
            #                       METHODS CONFIG                               #
            #____________________________________________________________________# 

            '''
                Method: proto_type
            '''
            if args['method'] == 'proto_type':
                if packet['type'] == 'tcp' and packet['ip']['s_addr'] != '10.1.5.2':
                    stat_type['tcp'] += 1
                elif packet['type'] == 'udp' and packet['ip']['s_addr'] != '10.1.5.2':
                    stat_type['udp'] += 1
                elif packet['type'] == 'icmp' and packet['ip']['s_addr'] != '10.1.5.2':
                    stat_type['icmp'] += 1
                
            '''
                Method: connection_stat
            '''
            if args['method'] == 'connection_stat':
                if packet['type'] == 'tcp':
                    p_state = filter_new_cons(packet)
                    s_addr=str(packet['ip']['s_addr'])
                    d_port=str(packet['tcp']['d_port'])

                    # new connection to 
                    if p_state == 10:
                        if s_addr+d_port not in ips['addr_port']:
                            ips['addr_port'].append(s_addr+d_port)
                            ips['packet'].append(str(packet['tcp']['d_port']))
                    # closing connection 
                    elif p_state == 12:
                        if s_addr+d_port not in ips2['addr_port']:
                            ips2['addr_port'].append(s_addr+d_port)
                            ips2['packet'].append(str(packet['tcp']['d_port']))


                    # get the established connections to 80
                    # these would only show up in tcpdump if data is transferred
                    # but then with different flags (PSH, etc.)
                    stat['est'] = SaltNetstat().run().next()

            '''
                Method: packets_from_ip
            '''
            if args['method'] == 'ppip':
                #print packet
                s_addr = str(packet['ip']['s_addr'])
                if s_addr not in ppip.keys() and packet['ip']['d_addr'] == '10.1.5.2':
                    ppip[s_addr] = {}
                    ppip[s_addr]['count'] = 1
                    if packet['type'] == 'tcp':
                        flags = get_flag(packet)
                        for flag in flags:
                            if flag not in ppip[s_addr].keys():
                                ppip[s_addr][flag]=1
                            else:
                                ppip[s_addr][flag]+=1
                elif s_addr in ppip.keys() and packet['ip']['d_addr'] == '10.1.5.2':
                    ppip[s_addr]['count'] += 1
                    if packet['type'] == 'tcp':
                        flags = get_flag(packet)
                        for flag in flags:
                            if flag not in ppip[s_addr].keys():
                                ppip[s_addr][flag]=1
                            else:
                                ppip[s_addr][flag]+=1



            #--------------------------------------------------------------------#
            #                       SHOWING STATS                                #
            #____________________________________________________________________#        

            #print only in interval
            if (s_time % args['ival']) == 0:
                if r_time != s_time:

                    '''
                            {{Method}}: connection start
                    '''
                    if args['method'] == 'connection_stat':
                        ports = {}
                        ports2 = {}
                        msg = ''
                        for packt_port in ips['packet']:
                            if packt_port not in ports.keys():
                                ports[packt_port]=1
                            else:
                                ports[packt_port]+=1
                        for p in ports.keys():
                            msg +=  "["+str(p)+"] <-> Number of different IPs : "+ str(ports[p])
                            #print list(set(ips['addr_port']))
                        for packt_port2 in ips2['packet']:
                            if packt_port2 not in ports2.keys():
                                ports2[packt_port2]=1
                            else:
                                ports2[packt_port]+=1

                        for po in ports2.keys():
                            msg += "["+str(po)+"] <-> fin: "+ str(ports2[po])+"\n"
                        if stat['est'] > 1:
                            msg += "[80] <-> Estabilished: "+str(stat['est'])
                        #printing the stats
                        print msg 
                        #cleaning the statistic                    
                        ips = {}
                        ips['addr_port'] = []
                        ips['packet'] = []

                        ips2 = {}
                        ips2['addr_port'] = []
                        ips2['packet'] = []

                        
                    '''
                            {{Method}}: proto_type
                    '''
                    if args['method'] == 'proto_type':
                        print "TCP/s: "+ str(stat_type['tcp']) + ' | UDP/s: '+ str(stat_type['udp']) +" | ICMP/s:"+ str(stat_type['icmp'])
                        for item in stat_type:
	                        stat_type[item] = 0


                    '''
                            {{Method}}: ppip
                    '''
                    if args['method'] == 'ppip':
                        for ip in ppip.keys():
                            print " ["+ ip + "] -> "+ str(ppip[ip]['count']) + "pkts/time | Flags: " + str(ppip[ip])

                    ppip = {}
                            
                                
                    print "\n"

                    # reset the so far collected stat
                    r_time = s_time
    except KeyboardInterrupt:
        sys.exit(1)

if __name__ == "__main__":
    main()
