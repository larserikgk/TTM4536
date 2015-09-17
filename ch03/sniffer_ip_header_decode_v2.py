#!/usr/bin/python2.7

import socket as socket_mod
import os
import struct
from ctypes import *

# host to listen on
host = "10.0.2.15"


class IP(Structure):
    _fields_ = [
        ("ihl",           c_ubyte, 4),
        ("version",       c_ubyte, 4),
        ("tos",           c_ubyte),
        ("len",           c_ushort),
        ("id",            c_ushort),
        ("offset",        c_ushort),
        ("ttl",           c_ubyte),
        ("protocol_num",  c_ubyte),
        ("sum",           c_ushort),
        ("src",           c_ulong),
        ("dst",           c_ulong)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)    

    def __init__(self, socket_buffer=None):

        # map protocol constants to their names
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

        # human readable IP addresses
        self.src_address = socket_mod.inet_ntoa(struct.pack("<L",self.src))

        self.dst_address = socket_mod.inet_ntoa(struct.pack("<L",self.dst))

        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

# create a raw socket and bind it to the public interface
if os.name == "nt":
    socket_protocol = socket_mod.IPPROTO_IP
else:
    #socket_protocol = socket_mod.IPPROTO_IP
    socket_protocol = socket_mod.IPPROTO_ICMP

sniffer = socket_mod.socket(socket_mod.AF_INET, socket_mod.SOCK_RAW, socket_protocol)
#sniffer = socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_RAW, socket_protocol)
sniffer.bind((host, 0))
#sniffer.bind(('lo', 0))

# we want the IP headers included in the capture
sniffer.setsockopt(socket_mod.IPPROTO_IP, socket_mod.IP_HDRINCL, 1)

# if we're on Windows we need to send some ioctls
# to setup promiscuous mode
if os.name == "nt":
    sniffer.ioctl(socket_mod.SIO_RCVALL, socket_mod.RCVALL_ON)

try:
    while True:
    
        # read in a single packet
        raw_buffer = sniffer.recvfrom(65565)[0]
    
        # create an IP header from the first 20 bytes of the buffer
        ip_header = IP(raw_buffer[0:20])
    
        print "Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
        
except KeyboardInterrupt:
    # if we're on Windows turn off promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket_mod.SIO_RCVALL, socket_mod.RCVALL_OFF)
