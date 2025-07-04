from scapy.all import *

def inject_packet(dst_ip, dst_port, message):
    pkt = IP(dst=dst_ip)/TCP(dport=dst_port)/Raw(load=message)
    send(pkt)
    print(f"[+] Injected packet to {dst_ip}:{dst_port}")
