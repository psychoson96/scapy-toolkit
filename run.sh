#!/usr/bin/env bash
# Bootstrap a local venv, install dependencies, then run the toolkit script you
# name. Everything after the script name is passed through to it verbatim.
#
# Usage:
#   ./run.sh <script.py> [args...]
#
# Examples:
#   sudo ./run.sh red_team_toolkit.py scan --target 192.168.1.10 --ports 22 80 443
#   sudo ./run.sh blue_team_toolkit.py --interface eth0 --mode scan
#   sudo ./run.sh purple_team.py --mode reverse --pcap capture.pcap
#   sudo ./run.sh red/port_scanner.py detect capture.pcap
#
# Note: sniffing/injection needs raw sockets — run those under sudo/root.
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <script.py> [args...]"
    echo "Example: sudo $0 blue_team_toolkit.py --interface eth0 --mode monitor"
    exit 1
fi

if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi

# shellcheck disable=SC1091
source venv/bin/activate

echo "[*] Installing dependencies..."
pip install -q -r requirements.txt

echo "[*] Running: $*"
exec python3 "$@"
