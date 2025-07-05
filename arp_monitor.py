## arp_monitor.py
```python
from scapy.all import sniff, ARP
from datetime import datetime

def detect_arp_spoof(pkt):
    if pkt.haslayer(ARP):
        print(f"[ARP] {pkt.psrc} is-at {pkt.hwsrc} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

print("[*] Monitoring ARP traffic...")
sniff(filter="arp", prn=detect_arp_spoof, store=0)
