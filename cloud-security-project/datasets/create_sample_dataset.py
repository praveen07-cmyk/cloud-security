import os
import csv
import random

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
os.makedirs(DATASETS_DIR, exist_ok=True)
FILE_PATH = os.path.join(DATASETS_DIR, "sample_intrusion_dataset.csv")

headers = [
    "Source Port", "Destination Port", "Protocol", "Flow Duration",
    "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Label"
]

labels = ["BENIGN", "DDoS", "PortScan", "Brute Force", "SQL Injection"]

rows = []
random.seed(42)

for _ in range(500):
    lbl = random.choice(labels)
    if lbl == "BENIGN":
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 53])
        proto = random.choice([6, 17])
        duration = random.randint(10, 5000)
        fwd_pkts = random.randint(1, 20)
        bwd_pkts = random.randint(1, 20)
        fwd_len = fwd_pkts * random.randint(40, 500)
        bwd_len = bwd_pkts * random.randint(40, 1000)
    elif lbl == "DDoS":
        src_port = random.randint(1024, 65535)
        dst_port = 80
        proto = 6
        duration = random.randint(1000, 100000)
        fwd_pkts = random.randint(100, 1000)
        bwd_pkts = random.randint(0, 10)
        fwd_len = fwd_pkts * 64
        bwd_len = bwd_pkts * 40
    elif lbl == "PortScan":
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1, 1024)
        proto = 6
        duration = random.randint(1, 100)
        fwd_pkts = 1
        bwd_pkts = random.choice([0, 1])
        fwd_len = 40
        bwd_len = 40 if bwd_pkts else 0
    elif lbl == "Brute Force":
        src_port = random.randint(1024, 65535)
        dst_port = 22
        proto = 6
        duration = random.randint(50, 500)
        fwd_pkts = random.randint(5, 30)
        bwd_pkts = random.randint(5, 30)
        fwd_len = fwd_pkts * 120
        bwd_len = bwd_pkts * 120
    else:  # SQL Injection
        src_port = random.randint(1024, 65535)
        dst_port = 443
        proto = 6
        duration = random.randint(20, 300)
        fwd_pkts = random.randint(2, 10)
        bwd_pkts = random.randint(2, 10)
        fwd_len = fwd_pkts * 350
        bwd_len = bwd_pkts * 500

    rows.append([src_port, dst_port, proto, duration, fwd_pkts, bwd_pkts, fwd_len, bwd_len, lbl])

with open(FILE_PATH, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(headers)
    writer.writerows(rows)

print(f"Generated synthetic intrusion dataset at {FILE_PATH} with {len(rows)} samples.")
