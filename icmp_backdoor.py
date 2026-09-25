#!/usr/bin/env python3
"""ICMP covert-channel DETECTOR (defensive).

This module previously contained an unauthenticated ICMP command-execution
backdoor (it piped attacker-supplied ICMP payloads straight into a shell).
That capability has been removed. What remains is the blue-team counterpart:
a passive sniffer that flags ICMP echo requests whose payload looks like a
command being smuggled over ICMP — the exact traffic such a backdoor produces.

It never executes anything. Run it on a host or span port to hunt for ICMP
tunneling / covert C2 on a network you are authorized to monitor.

Usage:
    sudo python3 icmp_backdoor.py [--iface eth0]
"""

import argparse
import logging

from scapy.all import ICMP, IP, Raw, sniff

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("icmp_detector")

# Substrings that suggest a command/shell payload rather than the benign,
# fixed filler bytes a normal ping carries.
SUSPICIOUS_TOKENS = (
    b"run:", b"cmd.exe", b"powershell", b"/bin/sh", b"/bin/bash",
    b"sh -i", b"wget", b"curl", b";", b"&&", b"|",
)


def inspect_icmp(pkt):
    """Log a warning when an ICMP echo request carries command-like data."""
    if not (pkt.haslayer(ICMP) and pkt.haslayer(Raw) and pkt.haslayer(IP)):
        return
    # type 8 == echo request (the direction a backdoor's commands travel).
    if pkt[ICMP].type != 8:
        return

    payload = bytes(pkt[Raw].load)
    hits = [tok.decode(errors="ignore") for tok in SUSPICIOUS_TOKENS if tok in payload]
    if hits:
        preview = payload[:120].decode(errors="ignore")
        logger.warning(
            "Suspicious ICMP payload from %s -> %s | tokens=%s | payload=%r",
            pkt[IP].src, pkt[IP].dst, ",".join(hits), preview,
        )


def main():
    parser = argparse.ArgumentParser(description="ICMP covert-channel detector (defensive)")
    parser.add_argument("--iface", help="Interface to sniff on (default: all)")
    args = parser.parse_args()

    logger.info("Starting ICMP covert-channel detector%s...",
                f" on {args.iface}" if args.iface else "")
    try:
        sniff(filter="icmp", prn=inspect_icmp, store=0, iface=args.iface)
    except PermissionError:
        logger.error("Raw socket access denied — re-run with sudo/root.")
    except KeyboardInterrupt:
        logger.info("Stopping detector.")


if __name__ == "__main__":
    main()
