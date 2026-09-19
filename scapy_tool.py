#!/usr/bin/env python3
"""Scapy Network Toolkit - unified command-line entry point.

This is the entry point referenced by ``run.sh`` and the README. It exposes
the three documented core capabilities behind a single command interface:

    sniff   Capture a fixed number of packets on an interface.
    scan    Run a TCP SYN port scan against a target host.
    detect  Scan a PCAP file for reverse-shell / suspicious keywords.

The heavier red/blue/purple tooling lives in the dedicated modules
(``red_team_toolkit.py``, ``blue_team_toolkit.py``, ``purple_team.py``);
this launcher intentionally stays small and dependency-light so the
documented quick-start commands "just work".

Intended for authorized testing, lab environments and educational use only.
"""

import argparse
import sys

# Keyword set used by the PCAP reverse-shell heuristic. Kept as bytes so we can
# match directly against raw packet payloads without decoding first.
REVERSE_SHELL_KEYWORDS = [
    b"cmd.exe",
    b"powershell",
    b"/bin/bash",
    b"/bin/sh",
    b"sh -i",
    b"bash",
    b"curl",
    b"wget",
    b"nc -e",
]


def _require_scapy():
    """Import scapy lazily and fail with a clear, actionable message.

    Scapy is an optional-at-install-time dependency; importing it lazily keeps
    ``--help`` usable even when scapy is not present and turns an opaque
    ImportError into guidance the user can act on.
    """
    try:
        from scapy.all import (  # noqa: F401  (re-exported for callers)
            IP,
            TCP,
            Raw,
            sniff,
            sr1,
            rdpcap,
        )
    except ImportError:
        sys.stderr.write(
            "[!] Scapy is not installed. Install it with:\n"
            "        pip install -r requirements.txt\n"
            "    or: pip install scapy\n"
        )
        sys.exit(1)
    return sniff, sr1, rdpcap, IP, TCP, Raw


def cmd_sniff(interface, count):
    """Capture ``count`` packets on ``interface`` and print a summary."""
    if count <= 0:
        sys.stderr.write("[!] count must be a positive integer\n")
        return 1
    sniff, _sr1, _rdpcap, _IP, _TCP, _Raw = _require_scapy()
    print(f"[*] Sniffing on {interface} for {count} packet(s)...")
    try:
        packets = sniff(iface=interface, count=count)
    except PermissionError:
        sys.stderr.write("[!] Permission denied. Packet capture usually requires root.\n")
        return 1
    except OSError as exc:
        sys.stderr.write(f"[!] Could not capture on '{interface}': {exc}\n")
        return 1
    packets.summary()
    return 0


def cmd_scan(target, start, end):
    """TCP SYN scan ``target`` across the inclusive port range start..end."""
    if start < 1 or end > 65535 or start > end:
        sys.stderr.write("[!] Invalid port range. Use 1 <= start <= end <= 65535.\n")
        return 1
    _sniff, sr1, _rdpcap, IP, TCP, _Raw = _require_scapy()
    print(f"[*] Scanning {target} ports {start}-{end}...")
    open_ports = []
    try:
        for port in range(start, end + 1):
            pkt = IP(dst=target) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=1, verbose=0)
            # 0x12 == SYN+ACK -> port is open and reachable.
            if resp is not None and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
                print(f"[+] Port {port} is open")
                open_ports.append(port)
    except PermissionError:
        sys.stderr.write("[!] Permission denied. Raw socket scanning requires root.\n")
        return 1
    if not open_ports:
        print("[*] No open ports found in the scanned range.")
    return 0


def cmd_detect(pcap_file):
    """Scan a PCAP file for reverse-shell / suspicious payload keywords."""
    _sniff, _sr1, rdpcap, _IP, _TCP, Raw = _require_scapy()
    print(f"[*] Analyzing {pcap_file} for suspicious keywords...")
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        sys.stderr.write(f"[!] PCAP file not found: {pcap_file}\n")
        return 1
    except Exception as exc:  # scapy raises assorted errors on malformed captures
        sys.stderr.write(f"[!] Could not read PCAP '{pcap_file}': {exc}\n")
        return 1

    found = 0
    for pkt in packets:
        if not pkt.haslayer(Raw):
            continue
        payload = bytes(pkt[Raw].load)
        for keyword in REVERSE_SHELL_KEYWORDS:
            if keyword in payload:
                found += 1
                print(f"[!] Found '{keyword.decode()}' in packet:")
                print(payload.decode(errors="ignore"))
                print("-" * 50)
                break  # one hit per packet is enough to flag it

    if found:
        print(f"[!] {found} suspicious packet(s) flagged.")
    else:
        print("[*] No suspicious keywords found.")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="scapy_tool.py",
        description="Scapy Network Toolkit - packet sniffer, port scanner and PCAP analyzer.",
    )
    subparsers = parser.add_subparsers(dest="command")

    sniff_parser = subparsers.add_parser("sniff", help="Sniff packets on an interface")
    sniff_parser.add_argument("interface", help="Network interface to sniff on (e.g. eth0)")
    sniff_parser.add_argument("count", type=int, help="Number of packets to capture")

    scan_parser = subparsers.add_parser("scan", help="TCP SYN port scan a target")
    scan_parser.add_argument("target", help="Target IP address or hostname")
    scan_parser.add_argument("start", type=int, help="Start port (1-65535)")
    scan_parser.add_argument("end", type=int, help="End port (1-65535)")

    detect_parser = subparsers.add_parser(
        "detect", help="Detect suspicious keywords in a PCAP file"
    )
    detect_parser.add_argument("pcap_file", help="Path to the .pcap file to analyze")

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "sniff":
        return cmd_sniff(args.interface, args.count)
    if args.command == "scan":
        return cmd_scan(args.target, args.start, args.end)
    if args.command == "detect":
        return cmd_detect(args.pcap_file)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
