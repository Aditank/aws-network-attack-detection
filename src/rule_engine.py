"""
Rule-Based Network Intrusion Detection Engine.
Applies expert cybersecurity domain rules to detect network anomalies and attacks
(DDoS, PortScan, SSH Brute Force, High Volume Traffic) without machine learning.
Optimized with high-performance vectorized NumPy/Pandas operations for large datasets.
"""

import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

class RuleBasedEngine:
    def __init__(self):
        pass

    def _extract_column(self, df, *possible_keys, default=0.0):
        """Finds column by possible exact or lowercase names, returning a numeric Series."""
        col_map = {str(c).lower().strip(): c for c in df.columns}
        for k in possible_keys:
            if k in df.columns:
                return pd.to_numeric(df[k], errors='coerce').fillna(default)
            kl = k.lower().strip()
            if kl in col_map:
                actual_k = col_map[kl]
                return pd.to_numeric(df[actual_k], errors='coerce').fillna(default)
        return pd.Series(default, index=df.index, dtype=float)

    def predict_dataframe(self, df):
        """
        Applies cybersecurity heuristics across an entire DataFrame using vectorized operations.
        Executes in milliseconds even for 100,000+ flow records.
        """
        df_results = df.copy()

        # Extract required flow attributes safely
        dest_port = self._extract_column(df, "Destination Port", "dst_port", "dport", "dest_port", "port")
        duration = self._extract_column(df, "Flow Duration", "duration", "dur")
        fwd_pkts = self._extract_column(df, "Total Fwd Packets", "fwd_packets", "fwd_pkts", "src_pkts")
        bwd_pkts = self._extract_column(df, "Total Backward Packets", "bwd_packets", "bwd_pkts", "dst_pkts")
        flow_pkts_s = self._extract_column(df, "Flow Packets/s", "flow_pkts_s", "rate")
        flow_bytes_s = self._extract_column(df, "Flow Bytes/s", "flow_bytes_s", "bytes_per_sec")
        syn_flag = self._extract_column(df, "SYN Flag Count", "syn", "syn_flag")
        ack_flag = self._extract_column(df, "ACK Flag Count", "ack", "ack_flag")

        # Vectorized Rule Conditions
        # Rule 1: DDoS High SYN packet rate
        cond_ddos = ((flow_pkts_s > 400) | (fwd_pkts > 100)) & (syn_flag == 1) & (ack_flag == 0)

        # Rule 2: Stealth Port Scan
        cond_portscan = (duration < 1000) & (fwd_pkts <= 3) & (bwd_pkts == 0) & (syn_flag == 1)

        # Rule 3: SSH Brute Force
        cond_ssh = (dest_port == 22) & (fwd_pkts > 15) & (duration > 1000)

        # Rule 4: Anomalous Bandwidth Surge
        cond_bandwidth = (flow_bytes_s > 1e6)

        # Assign attack flags and rule types in priority order
        conditions = [cond_ddos, cond_portscan, cond_ssh, cond_bandwidth]
        attack_types = ["DDoS", "PortScan", "SSH-Patator", "Suspicious-High-Bandwidth"]
        rule_names = ["RULE_DDOS_HIGH_SYN_RATE", "RULE_PORTSCAN_SINGLE_SYN", "RULE_SSH_PATATOR", "RULE_HIGH_BANDWIDTH"]

        df_results["Rule_Prediction"] = np.select(conditions, [1, 1, 1, 1], default=0)
        df_results["Rule_Attack_Type"] = np.select(conditions, attack_types, default="BENIGN")
        df_results["Rule_Triggered"] = np.select(conditions, rule_names, default="NO_RULE_TRIGGERED")

        return df_results

    def predict_record(self, row):
        """Single row evaluation fallback."""
        df_single = pd.DataFrame([row])
        res = self.predict_dataframe(df_single)
        return int(res["Rule_Prediction"].iloc[0]), str(res["Rule_Attack_Type"].iloc[0]), str(res["Rule_Triggered"].iloc[0])

def evaluate_rules(data_path="data/processed/cicids2017_cleaned.csv"):
    print("=" * 70)
    print("🛡️ EVALUATING RULE-BASED DETECTION ENGINE (VECTORIZED)")
    print("=" * 70)

    df = pd.read_csv(data_path)
    engine = RuleBasedEngine()
    evaluated_df = engine.predict_dataframe(df)

    y_true = evaluated_df["Is_Attack"]
    y_pred = evaluated_df["Rule_Prediction"]

    acc = accuracy_score(y_true, y_pred)
    cm = confusion_matrix(y_true, y_pred)

    print(f"\n📊 ACCURACY: {acc * 100:.2f}%\n")
    print("📋 CLASSIFICATION REPORT (0: Benign, 1: Attack):")
    print(classification_report(y_true, y_pred, target_names=["BENIGN", "ATTACK"]))

    print("🧩 CONFUSION MATRIX:")
    print(f"   True Negative: {cm[0][0]}")
    print(f"   False Positive: {cm[0][1]}")
    print(f"   False Negative: {cm[1][0]}")
    print(f"   True Positive:  {cm[1][1]}")
    print("=" * 70)

if __name__ == "__main__":
    evaluate_rules()
