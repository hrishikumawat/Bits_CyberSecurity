# Task 2.2B: Spoof an ICMP Echo Request. Spoof an ICMP echo request packet on behalf of another machine (i.e., using another machine’s IP address as its source IP address). This packet should be sent to a remote machine on the Internet (the machine must be alive). You should turn on your Wireshark, so if your spoofing is successful, you can see the echo reply coming back from the remote machine. 

from scapy.all import *

def spoof_pkt(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        print("Original packet")
        print("SRc IP : " + pkt[IP].src )
        print("Dst IP : " + pkt[IP].dst )

        ip = IP(src='8.8.8.8', dst=pkt[IP].src, ihl = pkt[IP].ihl, ttl = 99)

        icmp = ICMP(type=0, id=pkt[ICMP].id, seq =pkt[ICMP].seq)
        data = pkt[Raw].load
        newpkt = ip/icmp/data

        print("Spoofed packet")
        print("Src IP : " + newpkt[IP].src )
        print("Dst IP : " + newpkt[IP].dst )

        send(newpkt, verbose=0)

pkt = sniff(iface='br-19cac0a40c85', filter='icmp', prn = spoof_pkt)
