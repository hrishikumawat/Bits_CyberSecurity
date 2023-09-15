#task1.1B_3 Capture packets comes from or to go to a particular subnet. You can pick any subnet, such as 128.230.0.0/16; you should not pick the subnet that your VM is attached to

#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
  pkt.show()
pkt = sniff(iface='br-19cac0a40c85', filter='tcp dst port 23 and dst net 128.230.0.0/16', prn=print_pkt)
