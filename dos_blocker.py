import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP

#Maximum allows packets per a secodn rate
THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

def packet_callback(packet):
    #Extract the source IP address from the packet
    src_ip = packet[IP].src
    #Increment the packet count for the source IP address
    packet_count[src_ip] += 1
    #Record the current time
    current_time = time.time()
    #Calculate the time interval
    time_interval = current_time - start_time[0]

    #Evaulate if a DoS is happening every second
    if time_interval >= 1:
        for ip, count in packet_count.items():
            #Calculates the packet_rate
            packet_rate = count / time_interval
            #Check if THRESHOLD is exceeded and not already blocked
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                ####################################################
                ####                   IMPORTANT                ####
                ####################################################
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                #Add to blocked set
                blocked_ips.add(ip)

        #Clear and restart time for next interval
        packet_count.clear()
        start_time[0] = current_time

if __name__ == "__main__":
    #Check for root privledges
    if os.geteuid != 0:
        print("This script requires root privileges.")
        sys.exit(1)

    #Initalize packets dictionary for future IP, start time, and blocked set
    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")
    ####################################################
    ####                   IMPORTANT                ####
    ####################################################
    sniff(filter="ip", prn=packet_callback)