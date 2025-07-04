#!/bin/bash
# Activate venv and run Scapy Toolkit
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate
echo "[*] Installing dependencies..."
pip install -r requirements.txt

echo "[*] Running toolkit..."
python scapy_tool.py "$@"
