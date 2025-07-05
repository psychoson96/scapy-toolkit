# blue/icmp_monitor.py
from scapy.all import *
import datetime

def log_packet(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        print(f"[!] ICMP Echo Request from {pkt[IP].src} at {datetime.datetime.now()}")

print("[*] Starting ICMP monitor...")
sniff(filter="icmp", prn=log_packet, store=0)
