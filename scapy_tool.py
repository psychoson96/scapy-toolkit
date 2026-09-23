#!/usr/bin/env python3
"""Unified dispatcher for the Scapy Toolkit.

Routes to the red / blue / purple team toolkits so a single entry point
(and ./run.sh) can drive everything.

Examples:
    python3 scapy_tool.py red scan --target 192.168.1.10 --ports 22 80 443
    python3 scapy_tool.py blue --interface eth0 --mode monitor
    python3 scapy_tool.py purple --mode reverse --pcap capture.pcap
"""
import runpy
import sys

TOOLKITS = {
    "red": "red_team_toolkit.py",
    "blue": "blue_team_toolkit.py",
    "purple": "purple_team_toolkit.py",
}


def usage():
    print("Usage: python3 scapy_tool.py <red|blue|purple> [options...]")
    print()
    print("  red     Red Team Toolkit  (arp, scan, dns, inject)")
    print("  blue    Blue Team Toolkit (--mode monitor|scan|dns|arp)")
    print("  purple  Purple Team Toolkit (--mode reverse|hybrid|anomaly)")
    print()
    print("Run a sub-toolkit with -h for its own options, e.g.:")
    print("  python3 scapy_tool.py red -h")


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        usage()
        sys.exit(0 if len(sys.argv) < 2 else 0)

    team = sys.argv[1]
    script = TOOLKITS.get(team)
    if not script:
        print(f"[!] Unknown toolkit: {team}")
        usage()
        sys.exit(1)

    # Hand the remaining args to the target toolkit as if it were invoked directly.
    sys.argv = [script] + sys.argv[2:]
    runpy.run_path(script, run_name="__main__")


if __name__ == "__main__":
    main()
