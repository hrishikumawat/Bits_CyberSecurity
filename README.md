# Bits_CyberSecurity
This is the submisstion of first Cyber security Assignment submition.

Task 1

    1.1 - Sniffing Packets
    
        1.1B_1  The objective of this task is to spoof IP packets with an arbitrary source IP address. We will spoof ICMP echo request packets, and send them to another VM on the same network. 
        
        1.1B_2 Capture packets comes from or to go to a particular subnet. You can pick any subnet, such as 128.230.0.0/16; you should not pick the subnet that your VM is attached to

    1.2 - Spoofing ICMP Packets
    
    1.3 - Traceroute
    
    1.4 - Sniffing and-then Spoofing

Task 2

    2.1  Writing Packet Sniffing Program
    
        2.1A  Understanding How a Sniffer Works In this task, students need to write a sniffer program to print out the source and destination IP addresses of each captured packet.
        
        2.1B Writing Filters. Please write filter expressions for your sniffer program to capture each of the followings. You can find online manuals for pcap filters. In your Lab Assignment reports, you need to include screenshots to show the results after applying each of these filters. #• Capture the ICMP packets between two specific hosts. #• Capture the TCP packets with a destination port number in the range from 10 to 100. 
        
        2.1C  Sniffing Passwords. Please show how you can use your sniffer program to capture the password when somebody is using telnet on the network that you are monitoring. You may need to modify your sniffer code to print out the data part of a captured TCP packet (telnet uses TCP). It is acceptable if you print out the entire data part, and then manually mark where the password (or part of it) is.

    2.2 Spoofing
        2.2A Write a spoofing program. Please write your own packet spoofing program in C. You need to provide evidences (e.g., Wireshark packet trace) to show that your program successfully sends out spoofed IP packets.

        2.2B Spoof an ICMP Echo Request. Spoof an ICMP echo request packet on behalf of another machine (i.e., using another machine’s IP address as its source IP address). This packet should be sent to a remote machine on the Internet (the machine must be alive). You should turn on your Wireshark, so if your spoofing is successful, you can see the echo reply coming back from the remote machine. 


    2.3  Sniff and then Spoof: You need two machines on the same LAN. From machine A, you ping an IP X. This will generate an  ICMP echo request packet. If X is alive, the ping program will receive an echo reply, and print out the  esponse. Your sniff-and-then-spoof program runs on the attacker machine, which monitors the LAN through packet sniffing. Whenever it sees an ICMP echo request, regardless of what the target IPaddress is, your program should immediately send out an echo reply using the packet spoofing technique. Therefore,  regardless of whether machine X is alive or not, the ping program will always receive a reply, indicating that X is alive



Note: All the screenshots are included in the respective folders. The above given tree structure is followed for this assignment. 
