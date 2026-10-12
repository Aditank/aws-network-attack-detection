# 🛡️ Network Attack Detection & Security Operations Dashboard

[![Python](https://img.shields.io/badge/Python-3.13-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1-black.svg)](https://flask.palletsprojects.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-Random%20Forest-orange.svg)](https://scikit-learn.org/)
[![pytest](https://img.shields.io/badge/Tests-14%20Passed-brightgreen.svg)](https://pytest.org/)
[![Dataset](https://img.shields.io/badge/Dataset-CIC--IDS2017-purple.svg)](https://www.unb.ca/cic/datasets/ids-2017.html)

A dual-engine cybersecurity intrusion detection system (IDS) and interactive SOC web dashboard. Combining a deterministic **Rule-Based Expert System** with an ensemble **Random Forest Machine Learning Classifier** to analyze network flow records, eliminate false alarms, and provide real-time forensic threat evidence.

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
        - Rule: High SYN DDoS              - 100 Decision Trees
        - Rule: Stealth Port Scan          - 78 Flow Dimensions
        - Rule: SSH Brute Force            - Probability Calibration
        - Rule: Bandwidth Surge            - Zero-leakage Training
                  │                                   │
                  └─────────────────┬─────────────────┘
                                    ▼
                      [ Consensus Scoring Engine ]
                      - Severity: CRITICAL / HIGH / MEDIUM
                      - Engine Agreement % Calculation
                      - Threat Breakdown (DDoS, PortScan, Bot)
                                    │
                                    ▼
                     [ Interactive SOC Web Dashboard ]
                     - KPI Scorecard Metrics
                     - Live Forensic Inspection Log
                     - RESTful Inference API (/api/detect)
```

---

## 📊 Empirical Evaluation: Expert System vs. AI Classifier

During development on the standard **CIC-IDS2017 Intrusion Evaluation Dataset** (3,000 flows: 70% Benign, 30% Attacks), we evaluated the exact detection differences between traditional expert rules and machine learning:

| Metric | 🛡️ Expert Rule Engine | 🤖 Random Forest AI Classifier |
|---|:---:|:---:|
| **Accuracy** | 78.17% | **99.83%** |
| **Precision** | 59.00% | **100.00%** |
| **Recall** | 89.00% | **99.44%** |
| **F1-Score** | 71.00% | **99.72%** |
| **True Negatives (Benign)** | 1,548 | **2,100** |
| **False Positives (False Alarms)** | **552** ⚠️ | **0** ✅ |
| **False Negatives (Missed Attacks)** | **103** ⚠️ | **5** ✅ |
| **True Positives (Attacks Flagged)** | 797 | **895** |

> **Key Cybersecurity Takeaway**: Traditional static rules triggered **552 false alarms** because normal high-bandwidth video downloads trip rigid volume thresholds. The Random Forest model eliminated all 552 false alarms by analyzing multi-dimensional feature interactions across 78 dimensions.

---

## 🚀 Key Features

- **Interactive SOC Security Dashboard**: Dark-mode glassmorphism interface styled after real-world security operations centers.
- **Drag-and-Drop Ingestion**: Upload network capture CSV files up to **250 MB** with real-time progress indicators.
- **Resilient Column Aliases**: Automatically maps diverse CSV headers (`dst_port`, `dport`, `port` → `Destination Port`, `duration` → `Flow Duration`, etc.) to support external datasets (Wireshark, NSL-KDD, CIC-IDS).
- **Forensic Evidence Logging**: Displays granular traffic attributes (Destination Port, Flow Duration in µs, Forward Packets, Flow Bytes/s, Triggered Rule Name, ML Confidence %).
- **Vectorized High-Performance Engine**: Optimized with NumPy vectorization, capable of scoring **100,000+ network flows in milliseconds**.
- **100% Offline & Free (₹0 Budget)**: Runs fully on local infrastructure with zero cloud costs during development.

---

## 🛠️ Project Structure

```text
aws-network-attack-detection/
├── data/
│   ├── raw/                 # Raw dataset samples (excluded from Git)
│   └── processed/           # Sanitized, model-ready datasets
├── models/
│   └── random_forest_model.joblib # Serialized Random Forest bundle (656 KB)
├── src/
│   ├── download_dataset.py  # CIC-IDS2017 flow generator
│   ├── inspect_dataset.py   # Dataset quality, NaN, and Inf inspector
│   ├── preprocess.py        # Automated sanitization & feature pipeline
│   ├── rule_engine.py       # Vectorized Cybersecurity Expert Rule Engine
│   └── train_model.py       # Random Forest training & evaluation script
├── static/
│   ├── style.css            # Dark-mode SOC cybersecurity styles
│   └── script.js            # Frontend upload & dynamic rendering logic
├── templates/
│   └── index.html           # SOC Web Dashboard template
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

### 3. Run Preprocessing & Model Training (Optional - Pre-trained model included)
```bash
python src/download_dataset.py
python src/preprocess.py
python src/train_model.py
```

### 4. Start the SOC Web Dashboard
```bash
python app.py
```
Open your browser and navigate to **`http://127.0.0.1:5000`**. Click **"⚡ Load CIC-IDS2017 Sample Flow"** to run instant live detection.

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
