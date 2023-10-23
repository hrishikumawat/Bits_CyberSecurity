# Task 2.2A: Write a spoofing program. Please write your own packet spoofing program in C. You need to provide evidences (e.g., Wireshark packet trace) to show that your program successfully sends out spoofed IP packets.

from scapy.all import *

def spoof_pkt(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        print("Original packet")
        print("SRc IP : " + pkt[IP].src )
        print("Dst IP : " + pkt[IP].dst )

        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl = pkt[IP].ihl, ttl = 99)

        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        data = pkt[Raw].load
        newpkt = ip/icmp/data

        print("Spoofed packet")
        print("Src IP : " + newpkt[IP].src )
        print("Dst IP : " + newpkt[IP].dst )

        send(newpkt, verbose=0)

pkt = sniff(iface='br-19cac0a40c85', filter='icmp', prn = spoof_pkt)
