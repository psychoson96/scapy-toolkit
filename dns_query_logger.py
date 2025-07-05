## dns_query_logger.py
```python
from scapy.all import sniff, DNSQR, IP, UDP
from datetime import datetime

def log_dns_queries(packet):
    if packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode("utf-8", errors="ignore")
        src = packet[IP].src
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[+] DNS Query: {query} from {src} at {now}")

print("[*] Starting DNS query logger...")
sniff(filter="udp port 53", prn=log_dns_queries, store=0)
