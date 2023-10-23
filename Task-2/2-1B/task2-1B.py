# Task 2.1B: Writing Filters. Please write filter expressions for your sniffer program to capture each of the followings. You can find online manuals for pcap filters. In your Lab Assignment reports, you need to include screenshots to show the results after applying each of these filters. 
#• Capture the ICMP packets between two specific hosts. 
#• Capture the TCP packets with a destination port number in the range from 10 to 100. 

from scapy.all import *

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")

# Sniff packets
#• Capture the ICMP packets between two specific hosts. 
filter_exp_tcp = 'tcp and (dst portrange 10-100)'

#filter_exp_icmp = 'icmp and (host 192.168.0.100 and host 192.168.0.200)'


sniff(prn=packet_handler, filter=filter_exp_tcp, count=10)

#sniff(prn=packet_handler, filter=filter_exp_icmp, count=10)
