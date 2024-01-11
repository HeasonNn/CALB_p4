#!/usr/bin/python

import os
import sys
from scapy.all import *
import random

if os.getuid() !=0:
    print("ERROR: This script requires root privileges. se 'sudo' to run it.")
    quit()
    
try:
    ip_dst = sys.argv[1]
except:
    ip_dst = "20.0.0.2"

try:
    iface = sys.argv[2]
except:
    iface="veth1"    

# ip_src = "%d.%d.%d.%d" % (random.randint(1, 255), random.randint(0, 255),random.randint(0, 255), random.randint(0, 255))
if ip_dst == "20.0.0.2":
    ip_src = "20.0.0.1"
elif ip_dst == "20.0.0.1":
    ip_src = "20.0.0.2"

p = (Ether(dst="00:11:22:33:44:55", src="00:aa:bb:cc:dd:ee")/
        IP(src=ip_src, dst=ip_dst)/
        TCP(sport=random.randint(0, 65535),dport=random.randint(0, 65535))/
        "This is a test")
sendp(p, iface=iface) 

