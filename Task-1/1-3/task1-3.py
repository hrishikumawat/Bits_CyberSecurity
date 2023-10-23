#task 1.3 The objective of this task is to use Scapy to estimate the distance, in terms of number of routers, between your VM and a selected destination

from scapy.all import *

inRoute = True
i = 1
while i < 10 :
        a = IP(dst='8.8.8.8', ttl=i)
        response = sr1(a/ICMP(),timeout=2,verbose=0)

        if response is None:
                print(f"{i} Request timed out.")
                break
        elif response.type == 0:
                print(f"{i} {response.src}")
                inRoute = False
                break
        else:
                print(f"{i} {response.src}")
        i = i + 1
