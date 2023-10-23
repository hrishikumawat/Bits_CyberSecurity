# Task 1.1e objective of this task is to learn how to use Scapy to do packet sniffing in Python programs
#Task 1.1B-1 • Capture only the ICMP packet
#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
  pkt.show()
pkt = sniff(iface='br-19cac0a40c85', filter='icmp', prn=print_pkt)