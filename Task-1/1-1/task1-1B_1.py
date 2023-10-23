# Task 1.1B_2 Capture only the ICMP packet


#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
  pkt.show()
pkt = sniff(iface='br-19cac0a40c85', filter='tcp dst port 23', prn=print_pkt)
