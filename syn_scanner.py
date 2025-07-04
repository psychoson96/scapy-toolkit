from scapy.all import IP, TCP, sr1
import sys

def syn_scan(target, ports):
    print(f"[*] Scanning {target} for ports: {ports}")
    for port in ports:
        pkt = IP(dst=target)/TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
            print(f"[+] Port {port} is open")
        else:
            print(f"[-] Port {port} is closed or filtered")
