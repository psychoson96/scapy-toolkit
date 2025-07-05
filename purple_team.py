# Purple Team Toolkit (Unified Script)

```python
import argparse
import time
from collections import defaultdict
from datetime import datetime
from scapy.all import sniff, IP, TCP, Raw, rdpcap

# --- Reverse Shell PCAP Scanner ---
def find_reverse_shells(pcap_path):
    keywords = [b"cmd.exe", b"powershell", b"/bin/bash", b"/bin/sh", b"curl"]
    packets = rdpcap(pcap_path)
    for pkt in packets:
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            if any(keyword in payload for keyword in keywords):
                print(f"[!] Suspicious payload found: {payload}")

# --- Hybrid Sniffer Alert ---
def packet_callback(pkt):
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        if flags == 2:  # SYN
            print(f"[RED] SYN scan from {pkt[IP].src}")
        elif flags == 18:  # SYN-ACK
            print(f"[BLUE] SYN-ACK from {pkt[IP].src}")

# --- Behavioral Anomaly Logger ---
packets_per_ip = defaultdict(int)
start_time = time.time()
THRESHOLD = 50  # Packets per 10 seconds

def monitor_anomalies(packet):
    global start_time
    if packet.haslayer(IP):
        ip = packet[IP].src
        packets_per_ip[ip] += 1
    if time.time() - start_time >= 10:
        for ip, count in packets_per_ip.items():
            if count > THRESHOLD:
                print(f"[!] Anomaly detected: {ip} sent {count} packets in 10 seconds")
        packets_per_ip.clear()
        start_time = time.time()

# --- CLI ---
def main():
    parser = argparse.ArgumentParser(description="Purple Team Toolkit")
    parser.add_argument("--mode", choices=["reverse", "hybrid", "anomaly"], required=True, help="Choose the detection mode")
    parser.add_argument("--pcap", help="Path to pcap file (for reverse mode)")
    args = parser.parse_args()

    if args.mode == "reverse":
        if not args.pcap:
            print("[!] Please provide a pcap file with --pcap")
        else:
            find_reverse_shells(args.pcap)
    elif args.mode == "hybrid":
        print("[*] Running hybrid red/blue detection monitor...")
        sniff(filter="tcp", prn=packet_callback, store=0)
    elif args.mode == "anomaly":
        print("[*] Starting behavioral anomaly logger...")
        sniff(prn=monitor_anomalies, store=0)

if __name__ == "__main__":
    main()
```
