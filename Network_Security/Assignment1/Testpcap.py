#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Oct  8 10:04:54 2025

@author: deadman40
"""
import pandas as pd
from scapy.all import PcapReader

pkt = []

# Create a PcapReader object for your capture file
packets = PcapReader("gen-googleopen.pcap")

# Iterate through the packets
for packet in packets:
    # Process each packet here
    print(packet.summary()) # Example: print a summary of the packet

    # You can also access specific layers and fields
    if packet.haslayer("Ether"):
        print(f"Source MAC: {packet['Ether'].src}")
    if packet.haslayer("IP"):
        print(f"Source IP: {packet['IP'].src}, Destination IP: {packet['IP'].dst}")
    pkt.append(packet)
    
df = pd.DataFrame(pkt)



'''


The objective of this assignment is to analyze a capture file using Wireshark.

This learning objective is evaluated by examining the outputs.

Open the file “gen-googleopen. pcap” with WireShark and answer the following questions. 

You can perform this lab on your computer after installing Wireshark. 

1. What is the MAC address of the gateway (router)?   
    00:13:46:cc:a3:ea
2. What is the Name field's value in the first DNS query?  
    www.google.com
3. What layer 4 protocol is used in handling DNS queries and responses?  
    udp
4. What is the initial SYN number of the client (use the absolute number)?  
    2060517643
5. What is the initial SYN number of the server (use the absolute number)?  
    235066637
    
    
Please use the Part 2 Video to work along with your Wireshark activity. 





In [72]: pkt[3:5]
Out[72]: 
[<Ether  dst=00:22:5f:58:2b:0d src=00:13:46:cc:a3:ea type=IPv4 |<IP  version=4 ihl=5 tos=0x40 len=176 id=0 flags=DF frag=0 ttl=54 proto=udp chksum=0xc238 src=192.168.0.1 dst=192.168.0.115 |<UDP  sport=domain dport=50822 len=156 chksum=0xc66c |<DNS  id=34303 qr=1 opcode=QUERY aa=0 tc=0 rd=1 ra=1 z=0 ad=0 cd=0 rcode=ok qdcount=1 ancount=7 nscount=0 arcount=0 qd=[<DNSQR  qname=b'www.google.com.' qtype=A unicastresponse=0 qclass=IN |>] an=[<DNSRR  rrname=b'www.google.com.' type=CNAME cacheflush=0 rclass=IN ttl=436181 rdata=b'www.l.google.com.' |>, <DNSRR  rrname=b'www.l.google.com.' type=A cacheflush=0 rclass=IN ttl=64 rdata=74.125.19.105 |>, <DNSRR  rrname=b'www.l.google.com.' type=A cacheflush=0 rclass=IN ttl=64 rdata=74.125.19.147 |>, <DNSRR  rrname=b'www.l.google.com.' type=A cacheflush=0 rclass=IN ttl=64 rdata=74.125.19.103 |>, <DNSRR  rrname=b'www.l.google.com.' type=A cacheflush=0 rclass=IN ttl=64 rdata=74.125.19.99 |>, <DNSRR  rrname=b'www.l.google.com.' type=A cacheflush=0 rclass=IN ttl=64 rdata=74.125.19.106 |>, <DNSRR  rrname=b'www.l.google.com.' type=A cacheflush=0 rclass=IN ttl=64 rdata=74.125.19.104 |>] |>>>>,
 <Ether  dst=00:13:46:cc:a3:ea src=00:22:5f:58:2b:0d type=IPv4 |<IP  version=4 ihl=5 tos=0x0 len=52 id=20442 flags=DF frag=0 ttl=128 proto=tcp chksum=0x8be8 src=192.168.0.115 dst=74.125.19.105 |<TCP  sport=24730 dport=http seq=2060517643 ack=0 dataofs=8 reserved=0 flags=S window=8192 chksum=0x534e urgptr=0 options=[('MSS', 1460), ('NOP', None), ('WScale', 2), ('NOP', None), ('NOP', None), ('SAckOK', b'')] |>>>]

In [73]: pkt[0:5]
Out[73]: 
[<Ether  dst=ff:ff:ff:ff:ff:ff src=00:22:5f:58:2b:0d type=ARP |<ARP  hwtype=Ethernet (10Mb) ptype=IPv4 hwlen=6 plen=4 op=who-has hwsrc=00:22:5f:58:2b:0d psrc=192.168.0.115 hwdst=00:00:00:00:00:00 pdst=192.168.0.1 |>>,
 <Ether  dst=00:22:5f:58:2b:0d src=00:13:46:cc:a3:ea type=ARP |<ARP  hwtype=Ethernet (10Mb) ptype=IPv4 hwlen=6 plen=4 op=is-at hwsrc=00:13:46:cc:a3:ea psrc=192.168.0.1 hwdst=00:22:5f:58:2b:0d pdst=192.168.0.115 |<Padding  load=b'\xc0\xa8\x00s' |>>>,
 <Ether  dst=00:13:46:cc:a3:ea src=00:22:5f:58:2b:0d type=IPv4 |<IP  version=4 ihl=5 tos=0x0 len=60 id=20441 flags= frag=0 ttl=128 proto=udp chksum=0x6913 src=192.168.0.115 dst=192.168.0.1 |<UDP  sport=50822 dport=domain len=40 chksum=0xa276 |<DNS  id=34303 qr=0 opcode=QUERY aa=0 tc=0 rd=1 ra=0 z=0 ad=0 cd=0 rcode=ok qdcount=1 ancount=0 nscount=0 arcount=0 qd=[<DNSQR  qname=b'www.google.com.' qtype=A unicastresponse=0 qclass=IN |>] |>>>>,
 <Ether  dst=00:22:5f:58:2b:0d src=00:13:46:cc:a3:ea type=IPv4 |<IP  version=4 ihl=5 tos=0x40 len=176 id=0 flags=DF frag=0 ttl=54 proto=udp chksum=0xc238 src=192.168.0.1 dst=192.168.0.115 |<UDP  sport=domain dport=50822 len=156 chksum=0xc66c |<DNS  id=34303 qr=1 opcode=QUERY aa=0 tc=0 rd=1 ra=1 z=0 ad=0 cd=0 rcode=ok qdcount=1 ancount=7 nscount=0 arcount=0 qd=[<DNSQR  qname=b'www.google.com.' qtype=A unicastresponse=0 qclass=IN |>] an=[<DNSRR  rrname=b'www.google.com.' type=CNAME cacheflush=0 rclass=IN ttl=436181 rdata=b'www.l.google.com.' |>, <DNSRR  rrname=b'www.l.google.com.' type=A cacheflush=0 rclass=IN ttl=64 rdata=74.125.19.105 |>, <DNSRR  rrname=b'www.l.google.com.' type=A cacheflush=0 rclass=IN ttl=64 rdata=74.125.19.147 |>, <DNSRR  rrname=b'www.l.google.com.' type=A cacheflush=0 rclass=IN ttl=64 rdata=74.125.19.103 |>, <DNSRR  rrname=b'www.l.google.com.' type=A cacheflush=0 rclass=IN ttl=64 rdata=74.125.19.99 |>, <DNSRR  rrname=b'www.l.google.com.' type=A cacheflush=0 rclass=IN ttl=64 rdata=74.125.19.106 |>, <DNSRR  rrname=b'www.l.google.com.' type=A cacheflush=0 rclass=IN ttl=64 rdata=74.125.19.104 |>] |>>>>,
 <Ether  dst=00:13:46:cc:a3:ea src=00:22:5f:58:2b:0d type=IPv4 |<IP  version=4 ihl=5 tos=0x0 len=52 id=20442 flags=DF frag=0 ttl=128 proto=tcp chksum=0x8be8 src=192.168.0.115 dst=74.125.19.105 |<TCP  sport=24730 dport=http seq=2060517643 ack=0 dataofs=8 reserved=0 flags=S window=8192 chksum=0x534e urgptr=0 options=[('MSS', 1460), ('NOP', None), ('WScale', 2), ('NOP', None), ('NOP', None), ('SAckOK', b'')] |>>>]

In [74]: pkt[0:2]
Out[74]: 
[<Ether  dst=ff:ff:ff:ff:ff:ff src=00:22:5f:58:2b:0d type=ARP |<ARP  hwtype=Ethernet (10Mb) ptype=IPv4 hwlen=6 plen=4 op=who-has hwsrc=00:22:5f:58:2b:0d psrc=192.168.0.115 hwdst=00:00:00:00:00:00 pdst=192.168.0.1 |>>,
 <Ether  dst=00:22:5f:58:2b:0d src=00:13:46:cc:a3:ea type=ARP |<ARP  hwtype=Ethernet (10Mb) ptype=IPv4 hwlen=6 plen=4 op=is-at hwsrc=00:13:46:cc:a3:ea psrc=192.168.0.1 hwdst=00:22:5f:58:2b:0d pdst=192.168.0.115 |<Padding  load=b'\xc0\xa8\x00s' |>>>]

In [75]: pkt[3:5]
Out[75]: 
[<Ether  dst=00:22:5f:58:2b:0d src=00:13:46:cc:a3:ea type=IPv4 |<IP  version=4 ihl=5 tos=0x40 len=176 id=0 flags=DF frag=0 ttl=54 proto=udp chksum=0xc238 src=192.168.0.1 dst=192.168.0.115 |<UDP  sport=domain dport=50822 len=156 chksum=0xc66c |<DNS  id=34303 qr=1 opcode=QUERY aa=0 tc=0 rd=1 ra=1 z=0 ad=0 cd=0 rcode=ok qdcount=1 ancount=7 nscount=0 arcount=0 qd=[<DNSQR  qname=b'www.google.com.' qtype=A unicastresponse=0 qclass=IN |>] an=[<DNSRR  rrname=b'www.google.com.' type=CNAME cacheflush=0 rclass=IN ttl=436181 rdata=b'www.l.google.com.' |>, <DNSRR  rrname=b'www.l.google.com.' type=A cacheflush=0 rclass=IN ttl=64 rdata=74.125.19.105 |>, <DNSRR  rrname=b'www.l.google.com.' type=A cacheflush=0 rclass=IN ttl=64 rdata=74.125.19.147 |>, <DNSRR  rrname=b'www.l.google.com.' type=A cacheflush=0 rclass=IN ttl=64 rdata=74.125.19.103 |>, <DNSRR  rrname=b'www.l.google.com.' type=A cacheflush=0 rclass=IN ttl=64 rdata=74.125.19.99 |>, <DNSRR  rrname=b'www.l.google.com.' type=A cacheflush=0 rclass=IN ttl=64 rdata=74.125.19.106 |>, <DNSRR  rrname=b'www.l.google.com.' type=A cacheflush=0 rclass=IN ttl=64 rdata=74.125.19.104 |>] |>>>>,
 <Ether  dst=00:13:46:cc:a3:ea src=00:22:5f:58:2b:0d type=IPv4 |<IP  version=4 ihl=5 tos=0x0 len=52 id=20442 flags=DF frag=0 ttl=128 proto=tcp chksum=0x8be8 src=192.168.0.115 dst=74.125.19.105 |<TCP  sport=24730 dport=http seq=2060517643 ack=0 dataofs=8 reserved=0 flags=S window=8192 chksum=0x534e urgptr=0 options=[('MSS', 1460), ('NOP', None), ('WScale', 2), ('NOP', None), ('NOP', None), ('SAckOK', b'')] |>>>]

In [76]: pkt[3].show()
###[ Ethernet ]###
  dst       = 00:22:5f:58:2b:0d
  src       = 00:13:46:cc:a3:ea
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x40
     len       = 176
     id        = 0
     flags     = DF
     frag      = 0
     ttl       = 54
     proto     = udp
     chksum    = 0xc238
     src       = 192.168.0.1
     dst       = 192.168.0.115
     \options   \
###[ UDP ]###
        sport     = domain
        dport     = 50822
        len       = 156
        chksum    = 0xc66c
###[ DNS ]###
           id        = 34303
           qr        = 1
           opcode    = QUERY
           aa        = 0
           tc        = 0
           rd        = 1
           ra        = 1
           z         = 0
           ad        = 0
           cd        = 0
           rcode     = ok
           qdcount   = 1
           ancount   = 7
           nscount   = 0
           arcount   = 0
           \qd        \
            |###[ DNS Question Record ]###
            |  qname     = b'www.google.com.'
            |  qtype     = A
            |  unicastresponse= 0
            |  qclass    = IN
           \an        \
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.google.com.'
            |  type      = CNAME
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 436181
            |  rdlen     = None
            |  rdata     = b'www.l.google.com.'
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.l.google.com.'
            |  type      = A
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 64
            |  rdlen     = None
            |  rdata     = 74.125.19.105
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.l.google.com.'
            |  type      = A
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 64
            |  rdlen     = None
            |  rdata     = 74.125.19.147
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.l.google.com.'
            |  type      = A
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 64
            |  rdlen     = None
            |  rdata     = 74.125.19.103
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.l.google.com.'
            |  type      = A
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 64
            |  rdlen     = None
            |  rdata     = 74.125.19.99
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.l.google.com.'
            |  type      = A
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 64
            |  rdlen     = None
            |  rdata     = 74.125.19.106
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.l.google.com.'
            |  type      = A
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 64
            |  rdlen     = None
            |  rdata     = 74.125.19.104
           \ns        \
           \ar        \


In [77]: pkt[2].show()
###[ Ethernet ]###
  dst       = 00:13:46:cc:a3:ea
  src       = 00:22:5f:58:2b:0d
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 60
     id        = 20441
     flags     = 
     frag      = 0
     ttl       = 128
     proto     = udp
     chksum    = 0x6913
     src       = 192.168.0.115
     dst       = 192.168.0.1
     \options   \
###[ UDP ]###
        sport     = 50822
        dport     = domain
        len       = 40
        chksum    = 0xa276
###[ DNS ]###
           id        = 34303
           qr        = 0
           opcode    = QUERY
           aa        = 0
           tc        = 0
           rd        = 1
           ra        = 0
           z         = 0
           ad        = 0
           cd        = 0
           rcode     = ok
           qdcount   = 1
           ancount   = 0
           nscount   = 0
           arcount   = 0
           \qd        \
            |###[ DNS Question Record ]###
            |  qname     = b'www.google.com.'
            |  qtype     = A
            |  unicastresponse= 0
            |  qclass    = IN
           \an        \
           \ns        \
           \ar        \


In [78]: pkt[3].show()
###[ Ethernet ]###
  dst       = 00:22:5f:58:2b:0d
  src       = 00:13:46:cc:a3:ea
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x40
     len       = 176
     id        = 0
     flags     = DF
     frag      = 0
     ttl       = 54
     proto     = udp
     chksum    = 0xc238
     src       = 192.168.0.1
     dst       = 192.168.0.115
     \options   \
###[ UDP ]###
        sport     = domain
        dport     = 50822
        len       = 156
        chksum    = 0xc66c
###[ DNS ]###
           id        = 34303
           qr        = 1
           opcode    = QUERY
           aa        = 0
           tc        = 0
           rd        = 1
           ra        = 1
           z         = 0
           ad        = 0
           cd        = 0
           rcode     = ok
           qdcount   = 1
           ancount   = 7
           nscount   = 0
           arcount   = 0
           \qd        \
            |###[ DNS Question Record ]###
            |  qname     = b'www.google.com.'
            |  qtype     = A
            |  unicastresponse= 0
            |  qclass    = IN
           \an        \
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.google.com.'
            |  type      = CNAME
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 436181
            |  rdlen     = None
            |  rdata     = b'www.l.google.com.'
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.l.google.com.'
            |  type      = A
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 64
            |  rdlen     = None
            |  rdata     = 74.125.19.105
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.l.google.com.'
            |  type      = A
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 64
            |  rdlen     = None
            |  rdata     = 74.125.19.147
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.l.google.com.'
            |  type      = A
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 64
            |  rdlen     = None
            |  rdata     = 74.125.19.103
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.l.google.com.'
            |  type      = A
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 64
            |  rdlen     = None
            |  rdata     = 74.125.19.99
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.l.google.com.'
            |  type      = A
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 64
            |  rdlen     = None
            |  rdata     = 74.125.19.106
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.l.google.com.'
            |  type      = A
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 64
            |  rdlen     = None
            |  rdata     = 74.125.19.104
           \ns        \
           \ar        \


In [79]: pkt[3].show()
###[ Ethernet ]###
  dst       = 00:22:5f:58:2b:0d
  src       = 00:13:46:cc:a3:ea
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x40
     len       = 176
     id        = 0
     flags     = DF
     frag      = 0
     ttl       = 54
     proto     = udp
     chksum    = 0xc238
     src       = 192.168.0.1
     dst       = 192.168.0.115
     \options   \
###[ UDP ]###
        sport     = domain
        dport     = 50822
        len       = 156
        chksum    = 0xc66c
###[ DNS ]###
           id        = 34303
           qr        = 1
           opcode    = QUERY
           aa        = 0
           tc        = 0
           rd        = 1
           ra        = 1
           z         = 0
           ad        = 0
           cd        = 0
           rcode     = ok
           qdcount   = 1
           ancount   = 7
           nscount   = 0
           arcount   = 0
           \qd        \
            |###[ DNS Question Record ]###
            |  qname     = b'www.google.com.'
            |  qtype     = A
            |  unicastresponse= 0
            |  qclass    = IN
           \an        \
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.google.com.'
            |  type      = CNAME
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 436181
            |  rdlen     = None
            |  rdata     = b'www.l.google.com.'
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.l.google.com.'
            |  type      = A
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 64
            |  rdlen     = None
            |  rdata     = 74.125.19.105
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.l.google.com.'
            |  type      = A
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 64
            |  rdlen     = None
            |  rdata     = 74.125.19.147
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.l.google.com.'
            |  type      = A
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 64
            |  rdlen     = None
            |  rdata     = 74.125.19.103
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.l.google.com.'
            |  type      = A
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 64
            |  rdlen     = None
            |  rdata     = 74.125.19.99
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.l.google.com.'
            |  type      = A
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 64
            |  rdlen     = None
            |  rdata     = 74.125.19.106
            |###[ DNS Resource Record ]###
            |  rrname    = b'www.l.google.com.'
            |  type      = A
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 64
            |  rdlen     = None
            |  rdata     = 74.125.19.104
           \ns        \
           \ar        \


In [80]: pkt[4].show()
###[ Ethernet ]###
  dst       = 00:13:46:cc:a3:ea
  src       = 00:22:5f:58:2b:0d
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 52
     id        = 20442
     flags     = DF
     frag      = 0
     ttl       = 128
     proto     = tcp
     chksum    = 0x8be8
     src       = 192.168.0.115
     dst       = 74.125.19.105
     \options   \
###[ TCP ]###
        sport     = 24730
        dport     = http
        seq       = 2060517643
        ack       = 0
        dataofs   = 8
        reserved  = 0
        flags     = S
        window    = 8192
        chksum    = 0x534e
        urgptr    = 0
        options   = [('MSS', 1460), ('NOP', None), ('WScale', 2), ('NOP', None), ('NOP', None), ('SAckOK', b'')]


In [81]: pkt[5].show()
###[ Ethernet ]###
  dst       = 00:22:5f:58:2b:0d
  src       = 00:13:46:cc:a3:ea
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x20
     len       = 52
     id        = 54638
     flags     = 
     frag      = 0
     ttl       = 55
     proto     = tcp
     chksum    = 0x8f34
     src       = 74.125.19.105
     dst       = 192.168.0.115
     \options   \
###[ TCP ]###
        sport     = http
        dport     = 24730
        seq       = 235066637
        ack       = 2060517644
        dataofs   = 8
        reserved  = 0
        flags     = SA
        window    = 5720
        chksum    = 0x79ef
        urgptr    = 0
        options   = [('MSS', 1430), ('NOP', None), ('NOP', None), ('SAckOK', b''), ('NOP', None), ('WScale', 6)]


In [82]: 



'''