#Task 1.2 . The objective of this task is to spoof IP packets with an arbitrary source IP address. We will spoof ICMP echo request packets, and send them to another VM on the same network. 

from scapy.all import * 
a = IP()
a.src = '1.1.1.1'
a.dst = '10.0.0.1'
b = ICMP()
p = a/b
send(p)