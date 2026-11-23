#!/usr/bin/env python3
"""Generate a realistic synthetic network-flow CSV dataset for ShiftShield ML training."""
import numpy as np
import pandas as pd
from pathlib import Path

def generate():
    Path('data').mkdir(exist_ok=True)
    np.random.seed(42)

    CLASSES = ["Normal", "DoS", "DDoS", "PortScan", "BruteForce", "SQLInjection", "Botnet", "Exfiltration"]
    FEATURES = ["duration", "srcBytes", "dstBytes", "connCount", "sameSrvRate", "errorRate", "failedLogins", "uniquePorts", "srcIPs", "payloadEntropy"]

    BASE = [
        [2.0, 5.0, 5.0, 1.5, 0.8, 0.05, 0.0, 1.0, 1.0, 3.0],   # Normal
        [0.5, 3.0, 1.0, 5.0, 0.9, 0.70, 0.0, 1.0, 1.0, 2.0],   # DoS
        [0.5, 3.0, 1.0, 5.5, 0.9, 0.70, 0.0, 1.0, 6.0, 2.0],   # DDoS
        [0.7, 2.0, 1.0, 3.0, 0.3, 0.50, 0.0, 5.0, 1.0, 2.0],   # PortScan
        [1.5, 3.0, 2.0, 2.5, 0.5, 0.20, 4.0, 1.5, 1.0, 3.0],   # BruteForce
        [1.0, 6.0, 4.0, 1.5, 0.6, 0.30, 0.5, 1.0, 1.0, 6.0],   # SQLInjection
        [2.5, 2.5, 2.5, 2.0, 0.7, 0.10, 0.0, 2.0, 2.0, 5.0],   # Botnet
        [3.0, 2.0, 8.0, 1.5, 0.7, 0.05, 0.2, 1.5, 1.0, 6.5]    # Exfiltration
    ]

    rows = []
    for c_idx, label in enumerate(CLASSES):
        n_samples = 500 if label == "Normal" else 200
        means = BASE[c_idx]
        for _ in range(n_samples):
            vals = [max(0.0, round(float(np.random.normal(m, 0.25)), 4)) for m in means]
            row = dict(zip(FEATURES, vals))
            row['Label'] = label
            rows.append(row)

    df = pd.DataFrame(rows).sample(frac=1.0, random_state=42).reset_index(drop=True)
    out_path = Path('data/sample_network_flows.csv')
    df.to_csv(out_path, index=False)
    print(f"[ShiftShield] Generated {len(df)} flows across {len(CLASSES)} classes in {out_path}")
    return out_path

if __name__ == '__main__':
    generate()
