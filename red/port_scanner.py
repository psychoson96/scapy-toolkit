#!/usr/bin/env python3

import argparse
from scapy.all import *

def sniff_packets(interface, count):
    print(f"[*] Sniffing on {interface} for {count} packets...")
    packets = sniff(iface=interface, count=count)
    packets.summary()

def port_scan(target, start, end):
    print(f"[*] Scanning {target} ports {start}-{end}...")
    for port in range(start, end + 1):
        pkt = IP(dst=target)/TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
            print(f"[+] Port {port} is open")



from report_utils import write_to_csv

def detect_shell_keywords(pcap_file):
    keywords = [b"cmd.exe", b"bash", b"curl", b"powershell", b"wget", b"sh -i"]
    print(f"[*] Analyzing {pcap_file} for suspicious keywords...")
    packets = rdpcap(pcap_file)
    suspicious_rows = []
    for pkt in packets:
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            for keyword in keywords:
                if keyword in payload:
                    try:
                        decoded = payload.decode(errors='ignore')
                    except:
                        decoded = str(payload)
                    print(f"[!] Found '{keyword.decode()}' in packet:")
                    print(decoded)
                    print("-" * 50)
                    suspicious_rows.append([keyword.decode(), decoded[:100]])

    if suspicious_rows:
        write_to_csv("reverse_shell_alerts", ["Keyword", "Snippet"], suspicious_rows)
    else:
        print("[*] No suspicious keywords found.")

    keywords = [b"cmd.exe", b"bash", b"curl", b"powershell", b"wget", b"sh -i"]
    print(f"[*] Analyzing {pcap_file} for suspicious keywords...")
    packets = rdpcap(pcap_file)
    for pkt in packets:
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            for keyword in keywords:
                if keyword in payload:
                    print(f"[!] Found '{keyword.decode()}' in packet:")
                    print(payload.decode(errors='ignore'))
                    print("-" * 50)

def main():
    parser = argparse.ArgumentParser(description="Scapy-based Network Toolkit")
    subparsers = parser.add_subparsers(dest="command")

    sniff_parser = subparsers.add_parser("sniff", help="Sniff packets on an interface")
    sniff_parser.add_argument("interface", help="Network interface to sniff on")
    sniff_parser.add_argument("count", type=int, help="Number of packets to capture")

    scan_parser = subparsers.add_parser("scan", help="Port scan a target")
    scan_parser.add_argument("target", help="Target IP address")
    scan_parser.add_argument("start", type=int, help="Start port")
    scan_parser.add_argument("end", type=int, help="End port")

    detect_parser = subparsers.add_parser("detect", help="Detect suspicious keywords in a PCAP file")
    detect_parser.add_argument("pcap_file", help="Path to PCAP file")

    args = parser.parse_args()

    if args.command == "sniff":
        sniff_packets(args.interface, args.count)
    elif args.command == "scan":
        port_scan(args.target, args.start, args.end)
    elif args.command == "detect":
        detect_shell_keywords(args.pcap_file)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
