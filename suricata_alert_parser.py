## suricata_alert_parser.py
```python
import json

def parse_alerts(file_path):
    with open(file_path) as f:
        for line in f:
            try:
                entry = json.loads(line)
                if 'alert' in entry:
                    print(f"[{entry['alert']['severity']}] {entry['alert']['signature']} | {entry['src_ip']} -> {entry['dest_ip']}")
            except json.JSONDecodeError:
                continue
