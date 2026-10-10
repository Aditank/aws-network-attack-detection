"""
Dataset Preparation Script for AWS Network Attack Detection & Alerting System
Generates a standard, realistic sample of CIC-IDS2017 network traffic flows
with benign and malicious attack traffic (DDoS, PortScan, Bot, SSH-Patator).
Includes characteristic real-world quirks like infinite values and column spaces.
"""

import os
import numpy as np
import pandas as pd

def generate_cicids2017_sample(output_path="data/raw/cicids2017_sample.csv", n_samples=3000, random_state=42):
    np.random.seed(random_state)
    
    # Standard CIC-IDS2017 Column names (with authentic whitespace quirks)
    columns = [
        " Destination Port", " Flow Duration", " Total Fwd Packets", " Total Backward Packets",
        "Total Length of Fwd Packets", " Total Length of Bwd Packets", " Fwd Packet Length Max",
        " Fwd Packet Length Min", " Fwd Packet Length Mean", " Fwd Packet Length Std",
        "Bwd Packet Length Max", " Bwd Packet Length Min", " Bwd Packet Length Mean",
        " Bwd Packet Length Std", "Flow Bytes/s", " Flow Packets/s", " Flow IAT Mean",
        " Flow IAT Std", " Flow IAT Max", " Flow IAT Min", "Fwd IAT Total", " Fwd IAT Mean",
        " Fwd IAT Std", " Fwd IAT Max", " Fwd IAT Min", "Bwd IAT Total", " Bwd IAT Mean",
        " Bwd IAT Std", " Bwd IAT Max", " Bwd IAT Min", "Fwd PSH Flags", " Bwd PSH Flags",
        " Fwd URG Flags", " Bwd URG Flags", " Fwd Header Length", " Bwd Header Length",
        "Fwd Packets/s", " Bwd Packets/s", " Min Packet Length", " Max Packet Length",
        " Packet Length Mean", " Packet Length Std", " Packet Length Variance", "FIN Flag Count",
        " SYN Flag Count", " RST Flag Count", " PSH Flag Count", " ACK Flag Count",
        " URG Flag Count", " CWE Flag Count", " ECE Flag Count", " Down/Up Ratio",
        " Average Packet Size", " Avg Fwd Segment Size", " Avg Bwd Segment Size",
        " Fwd Header Length.1", "Fwd Avg Bytes/Bulk", " Fwd Avg Packets/Bulk", " Fwd Avg Bulk Rate",
        " Bwd Avg Bytes/Bulk", " Bwd Avg Packets/Bulk", " Bwd Avg Bulk Rate",
        "Subflow Fwd Packets", " Subflow Fwd Bytes", " Subflow Bwd Packets", " Subflow Bwd Bytes",
        "Init_Win_bytes_forward", " Init_Win_bytes_backward", " act_data_pkt_fwd",
        " min_seg_size_forward", "Active Mean", " Active Std", " Active Max", " Active Min",
        "Idle Mean", " Idle Std", " Idle Max", " Idle Min", " Label"
    ]
    
    # Label Distribution: 70% Benign, 15% DDoS, 8% PortScan, 4% Bot, 3% SSH-Patator
    labels = ["BENIGN"] * int(n_samples * 0.70) + \
             ["DDoS"] * int(n_samples * 0.15) + \
             ["PortScan"] * int(n_samples * 0.08) + \
             ["Bot"] * int(n_samples * 0.04) + \
             ["SSH-Patator"] * int(n_samples * 0.03)
    
    # Shuffle labels
    labels = np.random.choice(labels, size=len(labels), replace=False)
    actual_samples = len(labels)
    
    data = {}
    
    # Generate feature values based on traffic type characteristics
    dest_ports = []
    durations = []
    fwd_pkts = []
    bwd_pkts = []
    fwd_len_mean = []
    bwd_len_mean = []
    syn_flags = []
    ack_flags = []
    psh_flags = []
    flow_bytes_s = []
    flow_pkts_s = []
    
    for lbl in labels:
        if lbl == "BENIGN":
            dest_ports.append(np.random.choice([80, 443, 53, 22, 8080, 49152]))
            dur = np.random.exponential(scale=50000) + 100
            fp = np.random.randint(1, 25)
            bp = np.random.randint(1, 30)
            flm = np.random.uniform(40, 500)
            blm = np.random.uniform(40, 1200)
            syn = 1 if np.random.rand() < 0.15 else 0
            ack = 1 if np.random.rand() < 0.80 else 0
            psh = 1 if np.random.rand() < 0.40 else 0
        elif lbl == "DDoS":
            dest_ports.append(80)
            dur = np.random.exponential(scale=5000) + 10
            fp = np.random.randint(100, 1000)
            bp = np.random.randint(0, 5)
            flm = np.random.uniform(500, 1460)
            blm = np.random.uniform(0, 60)
            syn = 1 if np.random.rand() < 0.95 else 0
            ack = 0 if np.random.rand() < 0.85 else 1
            psh = 0
        elif lbl == "PortScan":
            dest_ports.append(np.random.randint(1, 1024))
            dur = np.random.uniform(1, 500)
            fp = np.random.randint(1, 3)
            bp = 0
            flm = np.random.uniform(0, 60)
            blm = 0
            syn = 1
            ack = 0
            psh = 0
        elif lbl == "Bot":
            dest_ports.append(np.random.choice([8080, 6667, 80]))
            dur = np.random.exponential(scale=100000)
            fp = np.random.randint(10, 80)
            bp = np.random.randint(10, 80)
            flm = np.random.uniform(100, 400)
            blm = np.random.uniform(100, 400)
            syn = 0
            ack = 1
            psh = 1 if np.random.rand() < 0.6 else 0
        elif lbl == "SSH-Patator":
            dest_ports.append(22)
            dur = np.random.uniform(1000, 20000)
            fp = np.random.randint(15, 50)
            bp = np.random.randint(15, 50)
            flm = np.random.uniform(200, 600)
            blm = np.random.uniform(200, 600)
            syn = 1 if np.random.rand() < 0.3 else 0
            ack = 1
            psh = 1
            
        durations.append(dur)
        fwd_pkts.append(fp)
        bwd_pkts.append(bp)
        fwd_len_mean.append(flm)
        bwd_len_mean.append(blm)
        syn_flags.append(syn)
        ack_flags.append(ack)
        psh_flags.append(psh)
        
        # Calculate rates with intentional division by zero / Inf quirks (matching real CIC-IDS2017)
        total_bytes = (fp * flm) + (bp * blm)
        total_pkts = fp + bp
        dur_sec = dur / 1e6  # duration in seconds
        
        if dur_sec <= 0.00001 and np.random.rand() < 0.05:
            flow_bytes_s.append(np.inf) # Real dataset artifact
            flow_pkts_s.append(np.inf)  # Real dataset artifact
        else:
            flow_bytes_s.append(total_bytes / max(dur_sec, 0.0001))
            flow_pkts_s.append(total_pkts / max(dur_sec, 0.0001))

    # Populate DataFrame columns
    df = pd.DataFrame()
    df[" Destination Port"] = dest_ports
    df[" Flow Duration"] = np.array(durations, dtype=np.int64)
    df[" Total Fwd Packets"] = fwd_pkts
    df[" Total Backward Packets"] = bwd_pkts
    df["Total Length of Fwd Packets"] = np.array(fwd_pkts) * np.array(fwd_len_mean)
    df[" Total Length of Bwd Packets"] = np.array(bwd_pkts) * np.array(bwd_len_mean)
    df[" Fwd Packet Length Max"] = np.array(fwd_len_mean) * 1.5
    df[" Fwd Packet Length Min"] = np.maximum(0, np.array(fwd_len_mean) * 0.5)
    df[" Fwd Packet Length Mean"] = fwd_len_mean
    df[" Fwd Packet Length Std"] = np.array(fwd_len_mean) * 0.25
    df["Bwd Packet Length Max"] = np.array(bwd_len_mean) * 1.5
    df[" Bwd Packet Length Min"] = np.maximum(0, np.array(bwd_len_mean) * 0.5)
    df[" Bwd Packet Length Mean"] = bwd_len_mean
    df[" Bwd Packet Length Std"] = np.array(bwd_len_mean) * 0.25
    
    df["Flow Bytes/s"] = flow_bytes_s
    df[" Flow Packets/s"] = flow_pkts_s
    
    df[" Flow IAT Mean"] = np.array(durations) / np.maximum(1, np.array(fwd_pkts) + np.array(bwd_pkts))
    df[" Flow IAT Std"] = df[" Flow IAT Mean"] * 0.3
    df[" Flow IAT Max"] = df[" Flow IAT Mean"] * 2.0
    df[" Flow IAT Min"] = np.maximum(0, df[" Flow IAT Mean"] * 0.1)
    
    # Fill remaining required columns with simulated values
    for col in columns:
        if col not in df.columns and col != " Label":
            if "Flags" in col or "Flag Count" in col:
                if "SYN" in col:
                    df[col] = syn_flags
                elif "ACK" in col:
                    df[col] = ack_flags
                elif "PSH" in col:
                    df[col] = psh_flags
                else:
                    df[col] = 0
            elif "Header Length" in col:
                df[col] = np.random.choice([20, 32, 40], size=actual_samples)
            else:
                df[col] = np.random.uniform(0, 100, size=actual_samples)
                
    # Add labels column
    df[" Label"] = labels
    
    # Introduce some NaN values to replicate real dataset quality issues
    nan_indices = np.random.choice(actual_samples, size=int(actual_samples * 0.01), replace=False)
    df.loc[nan_indices, "Flow Bytes/s"] = np.nan

    # Create target folder if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"✅ Generated {len(df)} records saved to {output_path}")
    print(f"📊 Class distribution:\n{df[' Label'].value_counts()}")

if __name__ == "__main__":
    generate_cicids2017_sample()
