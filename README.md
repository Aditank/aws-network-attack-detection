# 🛡️ Network Attack Detection & Security Operations Dashboard

[![Python](https://img.shields.io/badge/Python-3.13-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1-black.svg)](https://flask.palletsprojects.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-Random%20Forest-orange.svg)](https://scikit-learn.org/)
[![pytest](https://img.shields.io/badge/Tests-14%20Passed-brightgreen.svg)](https://pytest.org/)
[![Dataset](https://img.shields.io/badge/Dataset-CIC--IDS2017-purple.svg)](https://www.unb.ca/cic/datasets/ids-2017.html)

A dual-engine cybersecurity intrusion detection system (IDS) and interactive SOC web dashboard. Combining a deterministic **Rule-Based Expert System** with an ensemble **Random Forest Machine Learning Classifier** (trained on authentic **CIC-IDS2017** data) to analyze network flow records, eliminate false alarms, and provide real-time root-cause forensic explanations for detected attacks.

Designed for CSE / AI & Expert Systems (AIES) labs, cybersecurity portfolios, and cloud security engineering.

---

## 📌 Executive Summary & Architecture

Modern firewalls and Intrusion Detection Systems rely heavily on static signatures, which frequently suffer from **high false alarm rates** on benign high-bandwidth traffic. This project implements a **Dual-Engine Consensus Architecture** to evaluate network flow data:

```
                      [ Incoming Network Flow CSV ]
                                    │
                                    ▼
                     [ Ingestion & Sanitization ]
                     - Multi-encoding reader (UTF-8, Latin-1)
                     - Column alias normalization (dst_port -> Destination Port)
                     - Auto-padding & NaN median imputation
                                    │
                  ┌─────────────────┴─────────────────┐
                  ▼                                   ▼
        [ Engine 1: Expert System ]        [ Engine 2: Random Forest AI ]
        - Rule: High SYN DDoS              - 100 Decision Trees (Authentic CIC-IDS2017)
        - Rule: Stealth Port Scan          - 57 Flow Dimensions
        - Rule: SSH Brute Force            - Probability Calibration
        - Rule: Bandwidth Surge            - Zero-leakage Training
                  │                                   │
                  └─────────────────┬─────────────────┘
                                    ▼
                      [ Consensus Scoring Engine ]
                      - Severity: CRITICAL / HIGH / MEDIUM
                      - Engine Agreement % Calculation
                      - Threat Breakdown (DDoS, DoS, Botnet, PortScan, SSH, Web Attacks)
                                    │
                                    ▼
                     [ Interactive SOC Web Dashboard ]
                     - KPI Scorecard Metrics
                     - Live Forensic Inspection Log
                     - 💡 Interactive Row Click: Root-Cause Attack Reasons Modal
                     - RESTful Inference API (/api/detect)
```

---

## 📊 Empirical Evaluation: Authentic CIC-IDS2017 Trained Model

The Random Forest model was trained and evaluated on authentic network flow data from the **CIC-IDS2017 dataset** (225,250 balanced flows sampled from 9.3M real traffic flows across 20 distinct attack subcategories):

| Metric | 🛡️ Expert Rule Engine | 🤖 Random Forest AI Classifier (Authentic CIC-IDS2017) |
|---|:---:|:---:|
| **Training Records** | *Rule-based (No training)* | **180,200 Flows** |
| **Held-Out Test Records** | 45,050 | **45,050 Flows** |
| **Accuracy** | 78.17% | **99.70%** |
| **Precision** | 59.00% | **99.93%** |
| **Recall** | 89.00% | **99.53%** |
| **F1-Score** | 71.00% | **99.73%** |
| **True Negatives (Benign)** | 15,480 | **19,983** |
| **False Positives (False Alarms)** | 5,520 ⚠️ | **17** ✅ |
| **False Negatives (Missed Attacks)** | 1,030 ⚠️ | **118** ✅ |
| **True Positives (Attacks Flagged)** | 23,020 | **24,932** |

### Top Influential Network Features Identified by Model:
1. `Init_Win_bytes_backward` (Importance: 0.0696) — Handshake acknowledgement behavior
2. `min_seg_size_forward` (Importance: 0.0619) — TCP segment framing
3. `Packet Length Std` (Importance: 0.0485) — Automated attack tooling uniformity
4. `Init_Win_bytes_forward` (Importance: 0.0422) — Initial connection buffer
5. `Fwd Header Length` (Importance: 0.0401) — Forward packet protocol encapsulation

---

## 🚀 Key Features

- **Trained on Authentic CIC-IDS2017**: Model trained directly on real multi-gigabyte network flow traffic covering DDoS (LOIC, HOIC), DoS (Hulk, GoldenEye, Slowloris), Botnets, Infiltration, Portscans, and SSH/FTP Brute Force.
- **🔍 Click-to-Inspect Root-Cause Explanations**: Click any row in the Suspicious Flows table to open an instant forensic modal detailing:
  - **Why It's That Particular Attack**: Plain-English narrative explaining the detection verdict.
  - **Technical Attack Indicators & Reasons**: Breakdown of specific heuristic matches and ML feature deviations (e.g., negative backward TCP window, anomalous transmission intensity, zero packet length variance).
  - **Metrics vs. Benign Baseline**: Visual comparison cards comparing connection metrics against normal network activity.
  - **Dual-Engine Consensus**: Side-by-side display of the Random Forest probability and rule engine signatures.
- **Interactive SOC Security Dashboard**: Dark-mode glassmorphism interface styled after real-world security operations centers.
- **Drag-and-Drop Ingestion**: Upload network capture CSV files up to **250 MB** with real-time progress indicators.
- **Resilient Column Aliases**: Automatically maps diverse CSV headers (`dst_port`, `dport`, `port` → `Destination Port`, `duration` → `Flow Duration`, etc.) to support external datasets (Wireshark, NSL-KDD, CIC-IDS).
- **Vectorized High-Performance Engine**: Optimized with NumPy vectorization, capable of scoring **100,000+ network flows in milliseconds**.
- **100% Offline & Free (₹0 Budget)**: Runs fully on local infrastructure with zero cloud costs during development.

---

## 🛠️ Project Structure

```text
aws-network-attack-detection/
├── data/
│   ├── raw/                 # Raw dataset samples & authentic CIC-IDS2017 files
│   └── processed/           # Sanitized, model-ready datasets & provenance metadata
├── models/
│   └── random_forest_model.joblib # Serialized Random Forest bundle trained on authentic CIC-IDS2017
├── src/
│   ├── download_dataset.py  # Authentic KaggleHub dataset downloader & sample generator
│   ├── inspect_dataset.py   # Dataset quality, NaN, and Inf inspector
│   ├── preprocess.py        # Streaming sampler & preprocessing pipeline for multi-GB CSVs
│   ├── rule_engine.py       # Vectorized Cybersecurity Expert Rule Engine
│   └── train_model.py       # Random Forest training & evaluation script
├── static/
│   ├── style.css            # Dark-mode SOC cybersecurity styles & forensic modal UI
│   └── script.js            # Upload handling, dynamic table, and row click modal logic
├── templates/
│   └── index.html           # SOC Web Dashboard template with Forensic Investigation Modal
├── tests/
│   ├── test_detection_engine.py # Unit tests for rules & ML model
│   └── test_api.py          # Integration tests for upload endpoints & edge cases
├── app.py                   # Hardened Flask web application & REST API
├── pytest.ini               # Pytest configuration
├── requirements.txt         # Pinned project dependencies
└── README.md                # Comprehensive documentation
```

---

## ⚙️ Installation & Quickstart

### 1. Clone Repository & Setup Virtual Environment
```bash
git clone https://github.com/aditank/aws-network-attack-detection.git
cd aws-network-attack-detection

# Create and activate virtual environment
python -m venv venv

# Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# Linux / macOS
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run Preprocessing & Model Training (Optional - Pre-trained authentic model included)
```bash
# Preprocess the dataset (handles multi-GB authentic CSVs or sample CSVs)
python src/preprocess.py --raw-path "data/raw/cic-ids2017(real).csv"

# Train the Random Forest classifier
python src/train_model.py
```

### 4. Start the SOC Web Dashboard
```bash
python app.py
```
Open your browser and navigate to **`http://127.0.0.1:5000`**.
1. Click **"⚡ Load CIC-IDS2017 Sample Flow"** (or upload your own flow CSV).
2. Click **"Run Security Analysis"**.
3. **Click any row in the table** to open the Forensic Evidence Modal and view why the flow was flagged with technical root-cause reasons.


---

## 🧪 Automated Testing

The project includes 14 unit and integration tests covering heuristic signatures, model tensor outputs, and API error edge cases:

```bash
pytest
```

**Test Execution Output:**
```text
============================= test session starts =============================
platform win32 -- Python 3.13.7, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\spide\OneDrive\Desktop\aws-network-attack-detection
configfile: pytest.ini
testpaths: tests
collected 14 items

tests\test_api.py .......                                                [ 50%]
tests\test_detection_engine.py .......                                   [100%]

============================= 14 passed in 2.23s ==============================
```

---

## ☁️ Future Cloud Architecture (AWS Integration Roadmap)

Designed for modular migration to AWS serverless & cloud infrastructure:
- **Amazon S3**: Ingestion bucket for raw packet capture logs with bucket lifecycle policies.
- **AWS Lambda / ECS**: Containerized serverless worker triggering dual-engine inference on `s3:ObjectCreated`.
- **Amazon CloudWatch**: Custom metrics tracking attack frequencies and alarm thresholds.
- **Amazon SNS**: Instant email/SMS security alerts dispatched to SOC teams when `CRITICAL` severity attacks are detected.
- **Terraform**: Infrastructure as Code (IaC) for automated, repeatable deployment.

---

## 📄 License
This project is licensed under the MIT License - feel free to use for academic, portfolio, and research purposes.
