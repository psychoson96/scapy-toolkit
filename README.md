# Scapy Network Toolkit

A Python-based network security toolkit built with Scapy, for authorized
offensive and defensive use on networks you own or are permitted to test.

> ⚠️ **Authorized use only.** These tools send and capture raw traffic. Run them
> only on your own devices and networks, or where you have explicit written
> permission. Sniffing and packet injection require raw sockets — run under
> `sudo`/root.

## 🔧 Components

| Script | Team | What it does |
|---|---|---|
| `red_team_toolkit.py` | Red | ARP spoof, TCP SYN scan, DNS spoof, packet inject |
| `blue_team_toolkit.py` | Blue | Passive monitor, scan detection, DNS/ARP watch |
| `purple_team.py` | Purple | Reverse-shell PCAP scan, hybrid sniffer, anomaly logger |
| `red/port_scanner.py` | Red | Sniff, port scan, PCAP keyword detection (CSV report) |
| `syn_scanner.py` | Red | Standalone TCP SYN scanner |
| `icmp_backdoor.py` | Blue | Detector for ICMP covert-channel / command payloads |
| `arp_monitor.py`, `dns_query_logger.py`, `icmp_monitor.py` | Blue | Single-purpose passive monitors |
| `suricata_alert_parser.py` | Blue | Parse Suricata `eve.json` alerts |

## 📦 Requirements

- Python 3.8+
- Scapy (`scapy>=2.5.0`, see `requirements.txt`)
- Root/sudo for anything that captures or injects packets

## 🚀 Usage

`run.sh` bootstraps a venv, installs dependencies, and runs the script you name;
everything after the script name is passed through verbatim.

```bash
# Scan ports on a host you control
sudo ./run.sh red_team_toolkit.py scan --target 192.168.1.10 --ports 22 80 443

# Watch for port scans on an interface
sudo ./run.sh blue_team_toolkit.py --interface eth0 --mode scan

# Analyze a PCAP for reverse-shell keywords
./run.sh purple_team.py --mode reverse --pcap capture.pcap

# PCAP keyword detection with a CSV report
./run.sh red/port_scanner.py detect capture.pcap
```

You can also run any script directly (after installing scapy):

```bash
sudo python3 blue_team_toolkit.py --interface eth0 --mode monitor
```

## 📂 Reports

`red/port_scanner.py detect` writes findings to `reports/<name>_<timestamp>.csv`
via `utils/report_utils.py`.

## ⚠️ Known limitations

- No live automated tests (raw-socket tools need a network/root to exercise).
- `red/` modules and the unified `*_toolkit.py` scripts overlap; consolidation
  into a single package is a planned follow-up.

## 🧠 Author

Nelson Perez — Cybersecurity & Networking · [LinkedIn](https://www.linkedin.com/in/nmp2663)
