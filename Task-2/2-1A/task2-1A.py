# Task 2.1A: Understanding How a Sniffer Works In this task, students need to write a sniffer program to print out the source and destination IP addresses of each captured packet. S

from scapy.all import *

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")

# Sniff packets
sniff(prn=packet_handler, filter="ip", count=10)
