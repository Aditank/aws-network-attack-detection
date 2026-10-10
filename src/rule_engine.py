"""
Rule-Based Network Intrusion Detection Engine.
Applies expert cybersecurity domain rules to detect network anomalies and attacks
(DDoS, PortScan, SSH Brute Force, High Volume Traffic) without machine learning.
"""

import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

class RuleBasedEngine:
    def __init__(self):
        pass

    def predict_record(self, row):
        """
        Evaluates a single network flow record against rule heuristics.
        Returns (is_attack: int, attack_type: str, rule_triggered: str)
        """
        dest_port = row.get("Destination Port", 0)
        flow_duration = row.get("Flow Duration", 0)
        fwd_pkts = row.get("Total Fwd Packets", 0)
        bwd_pkts = row.get("Total Backward Packets", 0)
        flow_pkts_s = row.get("Flow Packets/s", 0)
        flow_bytes_s = row.get("Flow Bytes/s", 0)
        syn_flag = row.get("SYN Flag Count", 0)
        ack_flag = row.get("ACK Flag Count", 0)

        # Rule 1: High-Volume DDoS Flow Pattern
        if (flow_pkts_s > 400 or fwd_pkts > 100) and syn_flag == 1 and ack_flag == 0:
            return 1, "DDoS", "RULE_DDOS_HIGH_SYN_RATE"

        # Rule 2: Stealth Port Scan Signature
        if flow_duration < 1000 and fwd_pkts <= 3 and bwd_pkts == 0 and syn_flag == 1:
            return 1, "PortScan", "RULE_PORTSCAN_SINGLE_SYN"

        # Rule 3: SSH Brute Force Pattern
        if dest_port == 22 and fwd_pkts > 15 and flow_duration > 1000:
            return 1, "SSH-Patator", "RULE_SSH_PATATOR"

        # Rule 4: Anomalous Bandwidth Surge
        if flow_bytes_s > 1e6:
            return 1, "Suspicious-High-Bandwidth", "RULE_HIGH_BANDWIDTH"

        return 0, "BENIGN", "NO_RULE_TRIGGERED"

    def predict_dataframe(self, df):
        """Applies rule set across an entire DataFrame."""
        results = df.apply(self.predict_record, axis=1)
        predictions = [r[0] for r in results]
        attack_types = [r[1] for r in results]
        rules_triggered = [r[2] for r in results]

        df_results = df.copy()
        df_results["Rule_Prediction"] = predictions
        df_results["Rule_Attack_Type"] = attack_types
        df_results["Rule_Triggered"] = rules_triggered

        return df_results

def evaluate_rules(data_path="data/processed/cicids2017_cleaned.csv"):
    print("=" * 70)
    print("🛡️ EVALUATING RULE-BASED DETECTION ENGINE")
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
    print(f"   True Negative (Benign correctly identified):  {cm[0][0]}")
    print(f"   False Positive (Benign flagged as attack):  {cm[0][1]}")
    print(f"   False Negative (Attack missed by rules):    {cm[1][0]}")
    print(f"   True Positive (Attack correctly flagged):    {cm[1][1]}")
    print("=" * 70)

if __name__ == "__main__":
    evaluate_rules()
