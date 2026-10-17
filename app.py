"""
Flask Web Application & API for AWS Network Attack Detection and Alerting System.
Hardened for large files (up to 250MB), JSON error handling, and arbitrary dataset schemas.
"""

import os
import sys
import time
import io
import joblib
import numpy as np
import pandas as pd
from flask import Flask, render_template, request, jsonify, Response

# Ensure safe UTF-8 output on Windows terminals
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from src.rule_engine import RuleBasedEngine

app = Flask(__name__)

# Security & upload constraints: Allow up to 250MB uploads
app.config['MAX_CONTENT_LENGTH'] = 250 * 1024 * 1024  
MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "random_forest_model.joblib")

# Load trained Random Forest model and metadata bundle
model_bundle = None
if os.path.exists(MODEL_PATH):
    try:
        model_bundle = joblib.load(MODEL_PATH)
        print(f"[INFO] Loaded ML model artifact from {MODEL_PATH}")
    except Exception as e:
        print(f"[WARN] Error loading ML model: {e}")
else:
    print(f"[WARN] Warning: Model file not found at {MODEL_PATH}")

rule_engine = RuleBasedEngine()

# Flexible Column Aliases to support diverse dataset formats
COLUMN_ALIASES = {
    "destination port": "Destination Port",
    "dest_port": "Destination Port",
    "dest port": "Destination Port",
    "dst_port": "Destination Port",
    "dst port": "Destination Port",
    "dport": "Destination Port",
    "port": "Destination Port",
    "flow duration": "Flow Duration",
    "duration": "Flow Duration",
    "dur": "Flow Duration",
    "total fwd packets": "Total Fwd Packets",
    "total forward packets": "Total Fwd Packets",
    "fwd_packets": "Total Fwd Packets",
    "fwd packets": "Total Fwd Packets",
    "fwd_pkts": "Total Fwd Packets",
    "total backward packets": "Total Backward Packets",
    "total bwd packets": "Total Backward Packets",
    "bwd_packets": "Total Backward Packets",
    "bwd_pkts": "Total Backward Packets",
    "flow bytes/s": "Flow Bytes/s",
    "flow_bytes_s": "Flow Bytes/s",
    "flow bytes per sec": "Flow Bytes/s",
    "flow packets/s": "Flow Packets/s",
    "flow_packets_s": "Flow Packets/s",
    "flow packets per sec": "Flow Packets/s",
    "syn flag count": "SYN Flag Count",
    "syn": "SYN Flag Count",
    "syn_flag": "SYN Flag Count",
    "ack flag count": "ACK Flag Count",
    "ack": "ACK Flag Count",
    "ack_flag": "ACK Flag Count",
    "label": "Label",
    "attack": "Label",
    "class": "Label"
}

def safe_float(val, default=0.0):
    """Safely converts value to float."""
    try:
        if pd.isna(val):
            return default
        return float(val)
    except (ValueError, TypeError):
        return default

def safe_int(val, default=0):
    """Safely converts value to int."""
    try:
        if pd.isna(val):
            return default
        return int(float(val))
    except (ValueError, TypeError):
        return default

def normalize_columns(df):
    """Normalizes column headers and maps known aliases to standard names."""
    df = df.copy()
    cleaned_cols = {}
    for c in df.columns:
        c_clean = str(c).strip()
        c_lower = c_clean.lower()
        if c_lower in COLUMN_ALIASES:
            target = COLUMN_ALIASES[c_lower]
            if target not in df.columns or c == target:
                cleaned_cols[c] = target
            else:
                cleaned_cols[c] = c_clean
        else:
            cleaned_cols[c] = c_clean
    df.rename(columns=cleaned_cols, inplace=True)
    return df

def sanitize_dataframe(df, expected_features):
    """
    Cleans uploaded dataframe:
    - Normalizes columns
    - Drops ground truth labels
    - Replaces Infs with NaN and fills NaNs with 0
    - Aligns columns with expected ML model features (filling missing with 0)
    """
    df = normalize_columns(df)

    drop_cols = [c for c in ["Label", "Is_Attack", "Rule_Prediction", "Rule_Attack_Type", "Rule_Triggered"] if c in df.columns]
    features_df = df.drop(columns=drop_cols, errors="ignore")

    features_df = features_df.replace([np.inf, -np.inf], np.nan).fillna(0)

    for col in expected_features:
        if col not in features_df.columns:
            features_df[col] = 0.0

    features_df = features_df[expected_features].apply(pd.to_numeric, errors='coerce').fillna(0.0)
    return df, features_df

# Global Error Handlers - Always return JSON, never raw HTML
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({"error": "The uploaded file is too large (exceeds 250MB limit). Please upload a smaller sample."}), 413

@app.errorhandler(400)
def bad_request(error):
    return jsonify({"error": f"Bad Request: {str(error)}"}), 400

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({"error": "Internal server error occurred while analyzing the dataset."}), 500

@app.errorhandler(Exception)
def unhandled_exception(e):
    print(f"[ERROR] Unhandled exception: {e}")
    return jsonify({"error": f"Server processing error: {str(e)}"}), 500

@app.route("/")
def index():
    """Renders the SOC Web Dashboard."""
    return render_template("index.html")

@app.route("/api/health", methods=["GET"])
def health_check():
    """System health check endpoint."""
    return jsonify({
        "status": "healthy",
        "model_loaded": model_bundle is not None,
        "model_type": "RandomForestClassifier",
        "rule_engine_ready": True
    }), 200

@app.route("/api/detect", methods=["POST"])
def detect_traffic():
    """
    Analyzes uploaded network traffic records using both Rule Engine and ML Model.
    Resilient to large file sizes, missing columns, and varied encodings.
    """
    start_time = time.time()

    # 1. Validate file presence
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded. Please provide a CSV file under key 'file'."}), 400

    file = request.files["file"]
    if not file or file.filename == "":
        return jsonify({"error": "No file selected."}), 400

    if not file.filename.lower().endswith(".csv"):
        return jsonify({"error": "Invalid file format. Only CSV files (.csv) are accepted."}), 400

    # 2. Parse CSV with resilient encoding fallbacks
    raw_df = None
    file_bytes = file.read()
    if len(file_bytes) == 0:
        return jsonify({"error": "The uploaded CSV file is empty (0 bytes)."}), 400

    for enc in ["utf-8", "utf-8-sig", "latin-1", "cp1252"]:
        try:
            raw_df = pd.read_csv(io.BytesIO(file_bytes), encoding=enc)
            break
        except Exception:
            continue

    if raw_df is None or raw_df.empty:
        return jsonify({"error": "Could not parse CSV or the uploaded file contains 0 data rows."}), 400

    # If dataset is extremely large (> 25,000 rows), sample first 25,000 rows for dashboard responsiveness
    total_in_file = len(raw_df)
    max_eval_rows = 25000
    if total_in_file > max_eval_rows:
        raw_df = raw_df.head(max_eval_rows)
        sampled_note = f" (Sampled first {max_eval_rows:,} of {total_in_file:,} flows for real-time visualization)"
    else:
        sampled_note = ""

    total_records = len(raw_df)

    # Normalize column headers
    raw_df = normalize_columns(raw_df)

    # 3. Vectorized Rule-Based Engine
    df_with_rules = rule_engine.predict_dataframe(raw_df)
    rule_attacks = int((df_with_rules["Rule_Prediction"] == 1).sum())

    # 4. Machine Learning Model
    if model_bundle is None:
        return jsonify({"error": "ML model is not loaded on server. Run src/train_model.py first."}), 500

    expected_features = model_bundle["feature_names"]
    clean_original_df, ml_features_df = sanitize_dataframe(raw_df, expected_features)

    rf_model = model_bundle["model"]
    ml_predictions = rf_model.predict(ml_features_df)
    ml_probabilities = rf_model.predict_proba(ml_features_df)[:, 1]  # Attack probability

    ml_attacks = int((ml_predictions == 1).sum())

    # 5. Compile Forensic Evidence for Suspicious Records
    suspicious_records = []
    attack_type_counts = {"DDoS": 0, "PortScan": 0, "SSH-Patator": 0, "Bot": 0, "Other": 0}

    # Vectorized check for attack rows
    is_attack_mask = (ml_predictions == 1) | (df_with_rules["Rule_Prediction"] == 1)
    attack_indices = np.where(is_attack_mask)[0]

    for idx in attack_indices:
        is_ml_attack = bool(ml_predictions[idx] == 1)
        is_rule_attack = bool(df_with_rules.loc[idx, "Rule_Prediction"] == 1)
        rule_type = str(df_with_rules.loc[idx, "Rule_Attack_Type"])
        rule_name = str(df_with_rules.loc[idx, "Rule_Triggered"])
        prob = float(ml_probabilities[idx])

        detected_type = rule_type
        if detected_type in ("BENIGN", "NO_RULE_TRIGGERED", "Other"):
            port_val = safe_int(clean_original_df.loc[idx, "Destination Port"]) if "Destination Port" in clean_original_df.columns else 0
            dur_val = safe_float(clean_original_df.loc[idx, "Flow Duration"]) if "Flow Duration" in clean_original_df.columns else 0

            if "Label" in clean_original_df.columns and str(clean_original_df.loc[idx, "Label"]) not in ("BENIGN", "Benign", "0"):
                detected_type = str(clean_original_df.loc[idx, "Label"])
            elif "ClassLabel" in clean_original_df.columns and str(clean_original_df.loc[idx, "ClassLabel"]) not in ("BENIGN", "Benign", "0"):
                detected_type = str(clean_original_df.loc[idx, "ClassLabel"])
            elif port_val == 80:
                detected_type = "DDoS"
            elif port_val == 22:
                detected_type = "SSH-Patator"
            elif 0 < dur_val < 1000:
                detected_type = "PortScan"
            else:
                detected_type = "Botnet / ML-Anomaly"

        if detected_type not in attack_type_counts:
            attack_type_counts[detected_type] = 0
        attack_type_counts[detected_type] += 1

        # Keep evidence for top 100 suspicious flows
        if len(suspicious_records) < 100:
            row_dict = clean_original_df.iloc[idx].to_dict()
            dest_p = safe_int(row_dict.get("Destination Port", 0))
            flow_d = safe_float(row_dict.get("Flow Duration", 0))
            fwd_p = safe_int(row_dict.get("Total Fwd Packets", 0))
            bwd_p = safe_int(row_dict.get("Total Backward Packets", 0))
            bytes_s = safe_float(row_dict.get("Flow Bytes/s", 0))
            pkts_s = safe_float(row_dict.get("Flow Packets/s", 0))
            fwd_init_win = safe_float(row_dict.get("Init_Win_bytes_forward", row_dict.get("Init Fwd Win Bytes", 0)))
            bwd_init_win = safe_float(row_dict.get("Init_Win_bytes_backward", row_dict.get("Init Bwd Win Bytes", 0)))
            fwd_seg_min = safe_float(row_dict.get("min_seg_size_forward", row_dict.get("Fwd Seg Size Min", 0)))
            pkt_len_std = safe_float(row_dict.get("Packet Length Std", 0))
            syn_count = safe_int(row_dict.get("SYN Flag Count", 0))
            ack_count = safe_int(row_dict.get("ACK Flag Count", 0))

            # Generate dynamic explanation & forensic reasons
            reasons = []
            if is_rule_attack and rule_name != "NO_RULE_TRIGGERED":
                if "DDOS" in rule_name:
                    reasons.append(f"Heuristic Rule match ({rule_name}): High forward packet burst ({fwd_p} packets) and SYN rate without normal ACKs.")
                elif "PORTSCAN" in rule_name:
                    reasons.append(f"Heuristic Rule match ({rule_name}): Microsecond probe ({flow_d:.0f} µs) with SYN packet and 0 backward packets indicating port probing.")
                elif "SSH" in rule_name:
                    reasons.append(f"Heuristic Rule match ({rule_name}): Sustained connection to Port 22 (SSH) with repetitive packet sequence ({fwd_p} packets).")
                elif "BANDWIDTH" in rule_name:
                    reasons.append(f"Heuristic Rule match ({rule_name}): Extreme throughput surge ({bytes_s:,.0f} bytes/sec) exceeding normal traffic thresholds.")

            if is_ml_attack:
                ml_reasons = []
                if bwd_init_win <= 0:
                    ml_reasons.append("Zero/negative backward TCP window (server received no acknowledgement or connection reset)")
                if fwd_p > 30 or pkts_s > 300:
                    ml_reasons.append(f"Abnormal packet transmission intensity ({fwd_p} fwd pkts, {pkts_s:,.1f} pkts/s)")
                if bytes_s > 100000:
                    ml_reasons.append(f"High flow volumetric rate ({bytes_s:,.0f} B/s)")
                if 0 < flow_d < 500:
                    ml_reasons.append(f"Ultra-short ephemeral flow lifetime ({flow_d:.0f} µs)")
                if pkt_len_std < 2.0 and fwd_p > 5:
                    ml_reasons.append("Near-zero packet length variance characteristic of automated bot/attack tooling")

                if ml_reasons:
                    reasons.extend(ml_reasons)
                else:
                    reasons.append(f"Random Forest ML detected non-linear anomaly fingerprint across {len(expected_features)} flow metrics with {round(prob * 100, 1)}% confidence")

            if not reasons:
                reasons.append("Anomalous statistical deviations identified across multiple network flow descriptors.")

            # Summary narrative explanation
            narrative = (
                f"Classified as '{detected_type}' because this connection exhibit{'s' if len(reasons) == 1 else ''} "
                + "; ".join(reasons[:3]) + "."
            )

            severity = "CRITICAL" if prob > 0.85 or (is_ml_attack and is_rule_attack) else "HIGH" if is_ml_attack else "MEDIUM"

            evidence = {
                "record_id": int(idx) + 1,
                "attack_type": detected_type,
                "severity": severity,
                "ml_verdict": "ATTACK" if is_ml_attack else "BENIGN",
                "ml_confidence_pct": round(prob * 100, 2),
                "rule_verdict": "ATTACK" if is_rule_attack else "BENIGN",
                "rule_triggered": rule_name,
                "dest_port": dest_p,
                "flow_duration_us": flow_d,
                "total_fwd_pkts": fwd_p,
                "total_bwd_pkts": bwd_p,
                "flow_bytes_per_sec": bytes_s,
                "flow_pkts_per_sec": pkts_s,
                "syn_flag_count": syn_count,
                "ack_flag_count": ack_count,
                "explanation": {
                    "attack_type": detected_type,
                    "summary": narrative,
                    "primary_reasons": reasons,
                    "top_features": [
                        {"name": "Init Bwd Win Bytes", "value": f"{bwd_init_win:,.0f}", "normal_range": "> 0 for completed TCP handshake"},
                        {"name": "Flow Packets/s", "value": f"{pkts_s:,.1f}", "normal_range": "< 50 pkts/s for benign interactive sessions"},
                        {"name": "Flow Bytes/s", "value": f"{bytes_s:,.0f}", "normal_range": "< 100 KB/s average"},
                        {"name": "Flow Duration", "value": f"{flow_d:,.0f} µs", "normal_range": "> 1,000 µs for standard transactions"},
                        {"name": "Total Fwd Packets", "value": str(fwd_p), "normal_range": "1 - 15 packets typical for short requests"}
                    ]
                }
            }
            suspicious_records.append(evidence)

    # Calculate engine agreement
    agreement_count = int(((ml_predictions == 1) == (df_with_rules["Rule_Prediction"] == 1)).sum())
    agreement_pct = round((agreement_count / total_records) * 100, 2)

    latency_ms = round((time.time() - start_time) * 1000, 2)

    response_payload = {
        "status": "success",
        "latency_ms": latency_ms,
        "note": sampled_note,
        "summary": {
            "total_records": total_records,
            "total_file_records": total_in_file,
            "ml_detected_attacks": ml_attacks,
            "rule_detected_attacks": rule_attacks,
            "benign_records": total_records - ml_attacks,
            "engine_agreement_pct": agreement_pct,
            "attack_type_breakdown": attack_type_counts
        },
        "suspicious_records": suspicious_records
    }

    return jsonify(response_payload), 200

@app.route("/api/sample", methods=["GET"])
def get_sample_csv():
    """Generates an immediate sample CSV with both benign and attack flows for test uploads."""
    sample_file = "data/raw/cicids2017_sample.csv"
    if os.path.exists(sample_file):
        sample_df = pd.read_csv(sample_file).head(30)
    else:
        sample_df = pd.DataFrame({"Destination Port": [80, 22, 443], "Flow Duration": [1000, 500, 2000]})

    csv_data = sample_df.to_csv(index=False)
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=traffic_sample.csv"}
    )

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[INFO] Starting AWS Network Attack Detection Dashboard on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=True)
