import csv
import os
from datetime import datetime

def write_to_csv(report_name, headers, rows):
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = f"reports/{report_name}_{timestamp}.csv"
    with open(file_path, mode="w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    print(f"[+] Report saved to {file_path}")
