# Scapy Network Toolkit

A Python-based network security toolkit built with Scapy, designed for both offensive and defensive use cases.

## 🔧 Features

- **Packet Sniffer**: Capture packets on any network interface.
- **Port Scanner**: Basic TCP SYN scanner.
- **PCAP Analyzer**: Scan `.pcap` files for reverse shell keywords like `cmd.exe`, `bash`, `sh -i`, etc.

## 📖 Guides

- **[Flipper Zero Home-Lab Guide](docs/FLIPPER_ZERO_HOME_LAB_GUIDE.md)** — a hands-on
  workflow for testing *your own* network with a Flipper Zero (Momentum) + ESP32/Marauder,
  and feeding the findings into this Scapy toolkit. Authorized/lab use only.

## 📦 Requirements

- Python 3
- Scapy

Install with:

```bash
sudo apt update
sudo apt install -y python3-pip
pip3 install scapy
```

## 🚀 Usage

Run the tool with:

```bash
python3 scapy_tool.py [command] [options]
```

### Example Commands

Sniff 10 packets on `eth0`:
```bash
python3 scapy_tool.py sniff eth0 10
```

Scan ports 20-80 on 192.168.1.10:
```bash
python3 scapy_tool.py scan 192.168.1.10 20 80
```

Analyze a PCAP for reverse shells:
```bash
python3 scapy_tool.py detect reverse_shell_lab.pcap
---

## 📂 Usage Examples

### Analyze a PCAP for reverse shell activity:
```bash
./run.sh detect reverse_shell_lab.pcap
```

## 🧠 Author

Nelson Perez – Cybersecurity & Networking | [LinkedIn] (https://www.linkedin.com/in/nmp2663)

---
linkedin.com/in/nmp2663
