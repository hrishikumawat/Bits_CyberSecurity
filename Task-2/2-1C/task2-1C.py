# Task 2.1C: Sniffing Passwords. Please show how you can use your sniffer program to capture the password when somebody is using telnet on the network that you are monitoring. You may need to modify your sniffer code to print out the data part of a captured TCP packet (telnet uses TCP). It is acceptable if you print out the entire data part, and then manually mark where the password (or part of it) is 
from scapy.all import *

def packet_handler(packet):
        if packet[TCP].dport == 23: 
                payload = packet[TCP].payload
                print(payload) 

sniff(iface='br-19cac0a40c85',filter="tcp", prn=packet_handler)
