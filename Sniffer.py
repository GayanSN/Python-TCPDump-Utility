#!  /usr/bin/python3

import socket
from struct import *
from ctypes import *
from datetime import * 

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_ARP = 0x0806

class IPv4(Structure):
    _fields_ = [
            ("ver", c_ubyte, 4),
	    ("ihl", c_ubyte, 4),
            ("tos", c_ubyte),
            ("len", c_ushort),
            ("id", c_ushort),	
            ("offset", c_ushort),
            ("ttl", c_ubyte),
            ("protocol_num", c_ubyte),
            ("checksum", c_ushort),
            ("src", c_uint),
            ("dst", c_uint)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        ##map protocol constants to their names
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

        self.length = socket.ntohs(self.len)
        self.src_address = socket.inet_ntoa(pack("@I",self.src))
        self.dst_address = socket.inet_ntoa(pack("@I",self.dst))

        ##human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


class IPv6(Structure):
    _fields_ = [
            ("version", c_ubyte, 4),
            ("priority", c_ubyte),
            ("flow_label", c_uint, 20),
            ("len", c_ushort),
            ("next_header", c_ubyte),
            ("hop_limit", c_ubyte),
            ("src", c_ulonglong * 2),
            ("dst", c_ulonglong * 2)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        self.next_header_map = {6:"TCP", 17:"UDP", 58:"ICMPv6"}

        self.src_address = socket.inet_ntop(socket.AF_INET6, self.src)
        self.dst_address = socket.inet_ntop(socket.AF_INET6, self.dst)
        self.length = socket.ntohs(self.len)

        try:
            self.nxt_header = self.next_header_map[self.next_header]
        except:
            self.nxt_header = str(self.next_header)


class TCP(Structure):
    _fields_ = [
            ("src", c_ushort),
            ("dst", c_ushort),
            ("seq", c_uint),
            ("ack", c_uint),
            ("header_len", c_ubyte, 4),
            ("flags", c_ushort, 12),
            ("win_size", c_ushort),
            ("checksum", c_ushort),
            ("urgent_pointer", c_ushort)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        self.src_port = socket.ntohs(self.src)
        self.dst_port = socket.ntohs(self.dst)
        self.seq_num = socket.ntohl(self.seq)
        self.ack_num = socket.ntohl(self.ack)
        self.w_size = socket.ntohs(self.win_size)


class UDP(Structure):
    _fields_ = [
            ("src", c_ushort),
            ("dst", c_ushort),
            ("len", c_ushort),
            ("checksum", c_ushort)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        self.src_port = socket.ntohs(self.src)
        self.dst_port = socket.ntohs(self.dst)


class ICMP(Structure):
    _fields_ = [
            ("typ", c_ubyte),
            ("code", c_ubyte),
            ("checksum", c_ushort),
            ("identifier", c_ushort),
            ("seq_num", c_ushort)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.type_map = {0:"echo reply", 3:"destination unreachable", 8:"echo request"}

        self.id = socket.ntohs(self.identifier)
        self.seq = socket.ntohs(self.seq_num)

        try:
            self.type = self.type_map[self.typ]
        except:
            self.type = str(self.typ)

class ICMP6(Structure):
    _fields_ = [
            ("typ", c_ubyte),
            ("code", c_ubyte),
            ("checksum", c_ushort),
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.type_map = {128:"echo request", 129:"echo reply", 133:"router solicitation", 134:"router advertisement", \
                                135:"neighbor solicitation", 136:"neighbor advertisement"}

        try:
            self.type = self.type_map[self.typ]
        except:
            self.type = str(self.typ)


class ARP(Structure):
    _fields_ = [
            ("hardware_type", c_ushort),
            ("protocol_type", c_ushort),
            ("hardware_length", c_ubyte),
            ("protocol_length", c_ubyte),
            ("opcode", c_ushort),
            ("sen_hard_add", c_ubyte * 6),
            ("sen_prot_add", c_uint),
            ("trg_hard_add", c_ubyte * 6),
            ("trg_prot_add", c_uint)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        self.sprot_add = socket.inet_ntoa(pack("@I",self.sen_prot_add))
        self.tprot_add = socket.inet_ntoa(pack("@I",self.trg_prot_add))

        self.shard_add = self.format_to_hex(self.sen_hard_add)
        self.shard_add = ':'.join(self.shard_add[i:i+2] for i in range(0, len(self.shard_add), 2))

        self.htype = socket.ntohs(self.hardware_type)
        self.ptype = socket.ntohs(self.protocol_type)
        self.op = socket.ntohs(self.opcode)

    def format_to_hex(self, data):
        mac = "" 
        for i in data:
            mac += format(i, 'X')

        return mac 


class Ethernet(Structure):
    _fields_ = [
            ("dst", c_ubyte * 6),
            ("src", c_ubyte * 6),
            ("typ", c_ushort)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        self.type_map = {2048:"IPv4", 2054:"ARP", 34525:"IPv6"}
        self.t = socket.ntohs(self.typ)

        try:
            self.type = self.type_map[self.t]
        except:
            self.type = self.t

def decode_packets():
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('enp0s3', 0))
    except Exception as e:
        print(e)
        exit(1)

    while True:
        try:
            data = sock.recvfrom(65565)[0]
            eth = Ethernet(data[:14])
            ip = IPv4(data[14:])
            ip6 = IPv6(data[14:])
            arp = ARP(data[14:])
            tcp = TCP(data[34:])
            tcp6 = TCP(data[54:])
            udp = UDP(data[34:])
            udp6 = UDP(data[54:])
            icmp = ICMP(data[34:])
            icmp6 = ICMP6(data[54:])
            print(datetime.now().time(), end = ' ')


            if eth.type == "IPv4":
                if ip.protocol == "TCP":
                    print(f"IP {ip.src_address}:{tcp.src_port} -> {ip.dst_address}:{tcp.dst_port} : seq {tcp.seq_num}, ack {tcp.ack_num}, "\
                            f"win {tcp.w_size}, length {ip.length}") 

                elif ip.protocol == "UDP":
                    print(f"IP {ip.src_address}:{udp.src_port} -> {ip.dst_address}:{udp.dst_port} : {ip.protocol}, length {ip.length}")

                elif ip.protocol == "ICMP":
                    print(f"IP {ip.src_address}  ->  {ip.dst_address}: {ip.protocol} {icmp.type}, id {icmp.id}, seq {icmp.seq}, length "\
                            f"{ip.length}") 
            
            elif eth.type == "ARP":
                if arp.op == 1:
                    print(f"ARP, Request who-has {arp.tprot_add}  ->  tell {arp.sprot_add}")
            
                elif arp.op == 2:
                    print(f"ARP, Reply {arp.tprot_add}  ->  is-at {arp.shard_add}")

            elif eth.type == "IPv6":
                if ip6.nxt_header == "TCP":
                    print(f"IP6 {ip6.src_address}.{tcp6.src_port} > {ip6.dst_address}.{tcp6.dst_port} : seq {tcp6.seq_num}, ack {tcp6.ack_num},"\
                            f" win {tcp6.w_size}, length {ip6.length}")

                elif ip6.nxt_header == "UDP":
                    print(f"IP6 {ip6.src_address}.{udp6.src_port} > {ip6.dst_address}:{udp6.dst_port} : {ip6.protocol}, length {ip6.length}")

                elif ip6.nxt_header == "ICMP6":
                    print(f"IP6 {ip6.src_address}  >  {ip6.dst_address}: {ip6.protocol} {icmp6.type}, length {ip6.length}")

        except KeyboardInterrupt:
            print("\n[-] Exiting ....")
            exit(1)
        except ValueError:
            pass
        except Exception as e:
            print(e)


if __name__ == "__main__":
    decode_packets()
