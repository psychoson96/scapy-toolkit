import argparse
from scapy.all import sniff, IP, TCP, UDP, ARP
from collections import Counter
import time
from datetime import datetime

# --- Passive Traffic Monitor ---
def passive_monitor(interface):
    def monitor(pkt):
        if IP in pkt:
            print(f"[{pkt.time}] {pkt[IP].src} -> {pkt[IP].dst} | {pkt[IP].proto}")
    print(f"[*] Starting passive monitoring on {interface}")
    sniff(iface=interface, prn=monitor, store=0)

# --- Port Scan Detection ---
scan_counter = Counter()

def detect_scans(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
        ip = pkt[IP].src
        scan_counter[ip] += 1
        if scan_counter[ip] > 20:
            print(f"[!] Port scan detected from {ip}!")

# --- DNS Request Logger ---
def dns_logger(pkt):
    if pkt.haslayer(UDP) and pkt[UDP].dport == 53:
        print(f"[DNS] {pkt[IP].src} → DNS Query")

# --- ARP Watcher ---
def arp_watcher(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:
        print(f"[ARP] {pkt[ARP].psrc} is at {pkt[ARP].hwsrc}")

# --- CLI ---
def main():
    parser = argparse.ArgumentParser(description="Blue Team Network Defense Toolkit")
    parser.add_argument("--interface", required=True, help="Network interface to listen on")
    parser.add_argument("--mode", choices=["monitor", "scan", "dns", "arp"], required=True, help="Detection mode")
    args = parser.parse_args()

    if args.mode == "monitor":
        passive_monitor(args.interface)
    elif args.mode == "scan":
        print("[*] Detecting port scans...")
        sniff(iface=args.interface, prn=detect_scans, store=0)
    elif args.mode == "dns":
        print("[*] Logging DNS requests...")
        sniff(iface=args.interface, prn=dns_logger, store=0)
    elif args.mode == "arp":
        print("[*] Watching for ARP activity...")
        sniff(iface=args.interface, prn=arp_watcher, store=0)

if __name__ == "__main__":
    main()
