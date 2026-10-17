"""
Dataset Downloader & Organizer for Authentic CIC-IDS2017 Dataset
================================================================

Downloads and organizes genuine CIC-IDS network flow data from KaggleHub
('dhoogla/cicidscollection').

Guarantees:
-----------
1. Downloads authentic data via kagglehub without silent substitutions.
2. Recursively inspects the download directory.
   - If genuine CSVs are present, validates headers and organizes them.
   - If the collection is distributed as Parquet (as in dhoogla/cicidscollection),
     exports authentic network flow CSV partitions preserving original labels.
3. Organizes verified authentic CSV files under 'data/raw/cicids2017/'.
4. Does NOT generate synthetic data by default.
5. Fails clearly if network, authentication, or dataset download issues arise.
"""

import os
import sys
import shutil
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import pandas as pd

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

TARGET_RAW_DIR = os.path.join("data", "raw", "cicids2017")
KAGGLE_DATASET_HANDLE = "dhoogla/cicidscollection"

EXPECTED_FLOW_SIGNATURE_COLS = {
    "destination port",
    "flow duration",
    "total fwd packets",
    "total backward packets",
    "flow bytes/s",
    "fwd packets length total",
    "flow packets/s",
}


def validate_cicids_csv(file_path: str) -> Tuple[bool, str, List[str], Dict[str, int]]:
    """
    Validate that a CSV file is a genuine CIC-IDS network flow dataset.
    Checks:
    - File readability
    - Presence of 'Label' column
    - Presence of key network flow features
    - Sample class distribution

    Returns:
        (is_valid, reason, stripped_columns, sample_class_counts)
    """
    try:
        sample_df = pd.read_csv(file_path, nrows=500, encoding="utf-8", low_memory=False)
    except UnicodeDecodeError:
        try:
            sample_df = pd.read_csv(file_path, nrows=500, encoding="latin-1", low_memory=False)
        except Exception as e:
            return False, f"Failed to parse CSV: {e}", [], {}
    except Exception as e:
        return False, f"Failed to read CSV: {e}", [], {}

    if sample_df.empty or sample_df.shape[1] < 5:
        return False, "File is empty or has fewer than 5 columns", [], {}

    stripped_cols = [str(c).strip() for c in sample_df.columns]
    lower_cols = {c.lower(): c for c in stripped_cols}

    # 1. Validate 'Label' column exists
    label_col_actual = None
    for cand in ["label", "class", "classlabel"]:
        if cand in lower_cols:
            label_col_actual = lower_cols[cand]
            break

    if not label_col_actual:
        return False, f"Missing required 'Label' column (found: {stripped_cols[:8]}...)", stripped_cols, {}

    # 2. Check for network flow signatures
    matched_sigs = [sig for sig in EXPECTED_FLOW_SIGNATURE_COLS if sig in lower_cols]
    if len(matched_sigs) < 2:
        return False, f"Does not appear to be a CIC-IDS flow dataset (matched only {matched_sigs})", stripped_cols, {}

    class_counts = sample_df.iloc[:, [stripped_cols.index(label_col_actual)]].iloc[:, 0].astype(str).str.strip().value_counts().to_dict()

    return True, "Valid CIC-IDS flow CSV", stripped_cols, class_counts


def _export_parquet_to_authentic_csvs(
    parquet_path: str,
    target_dir: str,
    sample_size: int = 100000,
) -> List[str]:
    """
    Extracts authentic CIC-IDS flow partitions from Kaggle Parquet format
    into genuine, standard CSV files under target_dir.
    """
    try:
        import pyarrow.parquet as pq
    except ImportError:
        raise ImportError("pyarrow is required to parse parquet: pip install pyarrow")

    print(f"\n[EXTRACT] Reading authentic flows from Parquet collection: {parquet_path}")
    table = pq.read_table(parquet_path)
    df = table.to_pandas()

    print(f"   Total Authentic Rows in Parquet: {len(df):,}")
    print(f"   Available Attack Classes: {df['Label'].nunique()} categories")

    # Rename ClassLabel or ensure Label has the specific attack names
    if "Label" in df.columns and "ClassLabel" in df.columns:
        # Standardize: Label contains the attack type (DDoS, Portscan, etc.)
        pass

    os.makedirs(target_dir, exist_ok=True)
    generated_csvs = []

    # 1. General balanced authentic dataset (100,000 flows)
    benign_df = df[df["Label"].str.upper() == "BENIGN"]
    attack_df = df[df["Label"].str.upper() != "BENIGN"]

    n_attack = min(len(attack_df), int(sample_size * 0.35))
    n_benign = min(len(benign_df), sample_size - n_attack)

    atk_sample = attack_df.sample(n=n_attack, random_state=42)
    ben_sample = benign_df.sample(n=n_benign, random_state=42)
    combined_sample = pd.concat([ben_sample, atk_sample]).sample(frac=1.0, random_state=42)

    p1 = os.path.join(target_dir, "cicids_authentic_traffic.csv")
    combined_sample.to_csv(p1, index=False)
    generated_csvs.append(p1)
    print(f"   [CREATED] {p1} ({len(combined_sample):,} rows, {os.path.getsize(p1)/(1024*1024):.2f} MB)")

    # 2. Authentic DDoS-specific partition
    ddos_attacks = attack_df[attack_df["Label"].str.contains("DDoS", case=False, na=False)]
    if not ddos_attacks.empty:
        n_ddos = min(len(ddos_attacks), 15000)
        n_ben = min(len(benign_df), 35000)
        ddos_sample = pd.concat([
            benign_df.sample(n=n_ben, random_state=42),
            ddos_attacks.sample(n=n_ddos, random_state=42),
        ]).sample(frac=1.0, random_state=42)
        p2 = os.path.join(target_dir, "cicids_ddos_partition.csv")
        ddos_sample.to_csv(p2, index=False)
        generated_csvs.append(p2)
        print(f"   [CREATED] {p2} ({len(ddos_sample):,} rows, {os.path.getsize(p2)/(1024*1024):.2f} MB)")

    # 3. Authentic Bruteforce & Scanning partition
    probe_attacks = attack_df[
        attack_df["Label"].str.contains("Bruteforce|Portscan|SSH", case=False, na=False)
    ]
    if not probe_attacks.empty:
        n_probe = min(len(probe_attacks), 15000)
        n_ben = min(len(benign_df), 25000)
        probe_sample = pd.concat([
            benign_df.sample(n=n_ben, random_state=42),
            probe_attacks.sample(n=n_probe, random_state=42),
        ]).sample(frac=1.0, random_state=42)
        p3 = os.path.join(target_dir, "cicids_bruteforce_probe_partition.csv")
        probe_sample.to_csv(p3, index=False)
        generated_csvs.append(p3)
        print(f"   [CREATED] {p3} ({len(probe_sample):,} rows, {os.path.getsize(p3)/(1024*1024):.2f} MB)")

    return generated_csvs


def download_and_organize_cicids(
    target_dir: str = TARGET_RAW_DIR,
    dataset_handle: str = KAGGLE_DATASET_HANDLE,
    copy_files: bool = True,
) -> Dict[str, any]:
    """
    Downloads the CIC-IDS collection from KaggleHub and organizes
    valid CIC-IDS2017 files under target_dir.
    """
    try:
        import kagglehub
    except ImportError:
        raise ImportError(
            "kagglehub is required. Install it using: pip install kagglehub"
        )

    print("=" * 75)
    print(f"[DOWNLOAD] DOWNLOADING AUTHENTIC CIC-IDS DATASET VIA KAGGLEHUB")
    print(f"   Handle: {dataset_handle}")
    print("=" * 75)

    try:
        download_path = kagglehub.dataset_download(dataset_handle)
    except Exception as exc:
        print(f"\n[ERROR] Failed to download dataset via KaggleHub: {exc}")
        print("\nPossible causes:")
        print("1. No internet connectivity.")
        print("2. KaggleHub authentication / rate limit.")
        print("3. Dataset handle moved or unavailable.")
        raise RuntimeError(f"KaggleHub download failed: {exc}") from exc

    print(f"\n[OK] Download completed successfully!")
    print(f"   Kaggle cache location: {download_path}")

    # Inspect downloaded files recursively
    print("\n[SCAN] Recursively scanning downloaded files...")
    all_files = list(Path(download_path).rglob("*"))
    csv_candidates = [f for f in all_files if f.is_file() and f.suffix.lower() == ".csv"]
    parquet_candidates = [f for f in all_files if f.is_file() and f.suffix.lower() == ".parquet"]

    print(f"   Total items discovered:   {len(all_files)}")
    print(f"   CSV files discovered:     {len(csv_candidates)}")
    print(f"   Parquet files discovered: {len(parquet_candidates)}")

    os.makedirs(target_dir, exist_ok=True)
    verified_files = []
    rejected_files = []

    # If genuine CSV files are present in the Kaggle package
    if csv_candidates:
        print("\n[VALIDATION] Validating candidate CSV headers against CIC-IDS schema:")
        for csv_file in csv_candidates:
            size_mb = csv_file.stat().st_size / (1024 * 1024)
            is_valid, reason, cols, sample_classes = validate_cicids_csv(str(csv_file))

            if is_valid:
                print(f"   [VALID]   {csv_file.name} ({size_mb:.2f} MB)")
                print(f"             Classes in sample: {list(sample_classes.keys())[:5]}")
                dest_file = os.path.join(target_dir, csv_file.name)
                if copy_files:
                    if not os.path.exists(dest_file) or os.path.getsize(dest_file) != csv_file.stat().st_size:
                        print(f"             -> Copying to {dest_file}...")
                        shutil.copy2(str(csv_file), dest_file)
                    else:
                        print(f"             -> Already present in {dest_file}")
                verified_files.append({
                    "original_path": str(csv_file),
                    "dest_path": dest_file,
                    "filename": csv_file.name,
                    "size_mb": round(size_mb, 2),
                    "total_columns": len(cols),
                    "sample_classes": sample_classes,
                })
            else:
                print(f"   [EXCLUDE] {csv_file.name} ({size_mb:.2f} MB) - Reason: {reason}")
                rejected_files.append({
                    "path": str(csv_file),
                    "filename": csv_file.name,
                    "reason": reason,
                })

    # If the Kaggle dataset is packaged as authentic Parquet
    elif parquet_candidates:
        print("\n[INFO] Dataset is packaged as authentic Parquet collection.")
        print(f"       Exporting authentic partitions to genuine CSV files in {target_dir}...")
        exported = _export_parquet_to_authentic_csvs(str(parquet_candidates[0]), target_dir)
        for exp_path in exported:
            size_mb = os.path.getsize(exp_path) / (1024 * 1024)
            is_valid, reason, cols, sample_classes = validate_cicids_csv(exp_path)
            if is_valid:
                verified_files.append({
                    "original_path": str(parquet_candidates[0]),
                    "dest_path": exp_path,
                    "filename": os.path.basename(exp_path),
                    "size_mb": round(size_mb, 2),
                    "total_columns": len(cols),
                    "sample_classes": sample_classes,
                })

    else:
        raise FileNotFoundError(
            f"No CSV or Parquet data files found in downloaded directory: {download_path}"
        )

    print("=" * 75)
    print(f"[COMPLETE] CIC-IDS2017 ORGANIZED SUCCESSFULLY")
    print(f"   Target Directory:         {os.path.abspath(target_dir)}")
    print(f"   Verified Authentic CSVs:   {len(verified_files)}")
    print(f"   Excluded Non-Flow CSVs:   {len(rejected_files)}")
    print("=" * 75)

    return {
        "source_handle": dataset_handle,
        "kaggle_cache_path": download_path,
        "target_dir": target_dir,
        "verified_files": verified_files,
        "rejected_files": rejected_files,
    }


def generate_synthetic_demo_data(
    output_path: str = "data/raw/synthetic_demo.csv",
    n_samples: int = 3000,
    random_state: int = 42,
):
    """
    EXPLICIT DEMO DATA GENERATOR.
    Only run when explicitly requested via --generate-demo.
    Never run by default. Clearly marks output as SYNTHETIC.
    """
    import numpy as np

    print("=" * 75)
    print("[WARNING] GENERATING SYNTHETIC DEMO TRAFFIC DATA")
    print("   WARNING: This data is ARTIFICIAL and NOT authentic network traffic.")
    print(f"   Output destination: {output_path}")
    print("=" * 75)

    np.random.seed(random_state)
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

    labels = ["BENIGN"] * int(n_samples * 0.70) + \
             ["DDoS"] * int(n_samples * 0.15) + \
             ["PortScan"] * int(n_samples * 0.08) + \
             ["Bot"] * int(n_samples * 0.04) + \
             ["SSH-Patator"] * int(n_samples * 0.03)
    np.random.shuffle(labels)

    data = {c: np.random.uniform(10, 100, size=len(labels)) for c in columns if c != " Label"}
    data[" Label"] = labels

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df = pd.DataFrame(data)
    df.to_csv(output_path, index=False)
    print(f"[OK] Saved synthetic demo dataset ({len(df)} rows) to {output_path}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Download and organize genuine CIC-IDS2017 dataset via KaggleHub")
    parser.add_argument("--target-dir", default=TARGET_RAW_DIR, help="Destination directory for raw CIC-IDS2017 CSVs")
    parser.add_argument("--dataset-handle", default=KAGGLE_DATASET_HANDLE, help="KaggleHub dataset handle")
    parser.add_argument("--generate-demo", action="store_true", help="Explicitly generate artificial demo data (NOT real)")
    args = parser.parse_args()

    if args.generate_demo:
        generate_synthetic_demo_data()
    else:
        download_and_organize_cicids(target_dir=args.target_dir, dataset_handle=args.dataset_handle)
