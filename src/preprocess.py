"""
Data Preprocessing Pipeline for Authentic CIC-IDS2017 & Network Flow Datasets
==============================================================================

Processes authentic CIC-IDS2017 CSV files (including the 3.2GB real dataset
or individual partition CSVs) into a balanced, clean, memory-safe format
for Random Forest model training and detection evaluation.
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Union
import numpy as np
import pandas as pd

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

DEFAULT_RAW_DIR = os.path.join("data", "raw", "cicids2017")
DEFAULT_PROCESSED_CSV = os.path.join("data", "processed", "cicids2017_cleaned.csv")
DEFAULT_PROVENANCE_JSON = os.path.join("data", "processed", "data_provenance.json")

# Mapping from alternative CIC-IDS2017 column names to standard feature names
COLUMN_HARMONIZATION = {
    "Fwd Packets Length Total": "Total Length of Fwd Packets",
    "Bwd Packets Length Total": "Total Length of Bwd Packets",
    "Avg Packet Size": "Average Packet Size",
    "Init Fwd Win Bytes": "Init_Win_bytes_forward",
    "Init Bwd Win Bytes": "Init_Win_bytes_backward",
    "Fwd Act Data Packets": "act_data_pkt_fwd",
    "Fwd Seg Size Min": "min_seg_size_forward"
}

# Columns that MUST NEVER enter the model as features
TARGET_AND_METADATA_COLS = {
    "label",
    "classlabel",
    "is_attack",
    "source_file",
    "unnamed: 0",
    "index",
    "id",
}


def find_label_column(columns: List[str]) -> Optional[str]:
    """Find the column corresponding to the target label (case-insensitive)."""
    for col in columns:
        if str(col).strip().lower() in ("label", "class", "classlabel"):
            return col
    return None


def sample_large_real_dataset(
    file_path: str,
    target_samples_per_class: Dict[str, int] = None,
    chunksize: int = 200000,
    random_state: int = 42
) -> pd.DataFrame:
    """
    Efficiently streams through a multi-gigabyte CSV in chunks to sample a
    comprehensive, balanced dataset across all attack classes and benign traffic.
    """
    if target_samples_per_class is None:
        target_samples_per_class = {
            "Benign": 100000,
            "DDoS": 40000,
            "DoS": 25000,
            "Botnet": 20000,
            "Bruteforce": 20000,
            "Infiltration": 15000,
            "Webattack": 2995,
            "Portscan": 2255
        }

    collected_chunks = {cls: [] for cls in target_samples_per_class}
    collected_counts = {cls: 0 for cls in target_samples_per_class}
    
    print(f"\n⚡ Streaming multi-gigabyte file: {os.path.basename(file_path)}")
    print(f"   Target sample quotas: {target_samples_per_class}")

    np.random.seed(random_state)
    chunks_read = 0

    for chunk in pd.read_csv(file_path, chunksize=chunksize, low_memory=False):
        chunks_read += 1
        chunk.columns = chunk.columns.str.strip()

        # Identify class label column
        label_col = "ClassLabel" if "ClassLabel" in chunk.columns else ("Label" if "Label" in chunk.columns else None)
        if not label_col:
            raise ValueError("No label column found in stream chunk!")

        # Process each class target
        all_quotas_filled = True
        for cls_name, target_n in target_samples_per_class.items():
            needed = target_n - collected_counts[cls_name]
            if needed > 0:
                all_quotas_filled = False
                # Filter chunk for this class
                cls_rows = chunk[chunk[label_col].astype(str).str.strip().str.lower() == cls_name.lower()]
                if not cls_rows.empty:
                    take_n = min(len(cls_rows), needed)
                    sample = cls_rows.sample(n=take_n, random_state=random_state) if len(cls_rows) > take_n else cls_rows
                    collected_chunks[cls_name].append(sample)
                    collected_counts[cls_name] += len(sample)

        print(f"   Chunk {chunks_read}: Collected so far -> {collected_counts}")

        if all_quotas_filled:
            print("   ✔ All class quotas successfully reached!")
            break

    # Combine all collected rows
    all_dfs = []
    for cls_name, df_list in collected_chunks.items():
        if df_list:
            all_dfs.extend(df_list)

    if not all_dfs:
        raise ValueError("No rows collected from stream!")

    result_df = pd.concat(all_dfs, ignore_index=True)
    # Shuffle
    result_df = result_df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    print(f"   ✔ Sampling complete. Total rows assembled: {len(result_df):,}")
    return result_df


def preprocess_dataset(
    raw_path: str = DEFAULT_RAW_DIR,
    output_path: str = DEFAULT_PROCESSED_CSV,
    provenance_path: str = DEFAULT_PROVENANCE_JSON,
    max_rows_per_file: Optional[int] = 50000,
    selected_files: Optional[List[str]] = None,
) -> Dict[str, any]:
    """
    Preprocess authentic network traffic CSVs.
    Handles the 3.2GB cic-ids2017(real).csv intelligently via balanced streaming.
    """
    print("=" * 75)
    print(f"🧹 STARTING DATA PREPROCESSING WORKFLOW")
    print(f"   Input Source: {raw_path}")
    print("=" * 75)

    # 1. Check if raw_path is the 3.2GB real file
    if os.path.isfile(raw_path) and "real" in os.path.basename(raw_path).lower():
        input_files = [raw_path]
        is_large_real_csv = True
    elif os.path.isfile(raw_path):
        input_files = [raw_path]
        is_large_real_csv = False
    elif os.path.isdir(raw_path):
        all_csvs = sorted(list(Path(raw_path).glob("*.csv")))
        if not all_csvs:
            raise FileNotFoundError(f"No CSV files found in directory: {raw_path}")
        input_files = [str(f) for f in all_csvs]
        is_large_real_csv = False
    else:
        # Check if real CSV exists in data/raw
        real_csv_candidate = os.path.join("data", "raw", "cic-ids2017(real).csv")
        if os.path.exists(real_csv_candidate):
            input_files = [real_csv_candidate]
            is_large_real_csv = True
        elif os.path.exists("data/raw/cicids2017_sample.csv"):
            input_files = ["data/raw/cicids2017_sample.csv"]
            is_large_real_csv = False
        else:
            raise FileNotFoundError(f"Input source path does not exist: {raw_path}")

    # Determine authentic vs synthetic provenance
    is_synthetic = any("synthetic" in f.lower() or "sample" in f.lower() for f in input_files)
    provenance_type = "SYNTHETIC-DEMO" if is_synthetic else "AUTHENTIC-CICIDS2017"

    print(f"\n📂 Identified {len(input_files)} source CSV file(s) [Provenance: {provenance_type}]:")
    for f in input_files:
        size_mb = os.path.getsize(f) / (1024 * 1024)
        print(f"   - {os.path.basename(f)} ({size_mb:.2f} MB)")

    # 2. Load and Harmonize Data
    loaded_dfs = []
    source_manifest = []

    for f_path in input_files:
        fname = os.path.basename(f_path)
        if is_large_real_csv:
            df_file = sample_large_real_dataset(f_path)
        else:
            try:
                df_file = pd.read_csv(f_path, nrows=max_rows_per_file, encoding="utf-8", low_memory=False)
            except UnicodeDecodeError:
                df_file = pd.read_csv(f_path, nrows=max_rows_per_file, encoding="latin-1", low_memory=False)
        
        df_file.columns = df_file.columns.str.strip()
        
        # Harmonize column names (e.g. Fwd Packets Length Total -> Total Length of Fwd Packets)
        df_file.rename(columns=COLUMN_HARMONIZATION, inplace=True)

        # Normalize label column
        label_col = find_label_column(df_file.columns)
        if label_col and label_col != "Label":
            df_file.rename(columns={label_col: "Label"}, inplace=True)

        rows_read = len(df_file)
        class_dist = df_file["Label"].astype(str).str.strip().value_counts().to_dict()
        print(f"   ✔ Rows loaded: {rows_read:,} | Columns: {df_file.shape[1]}")
        print(f"     Class breakdown: {class_dist}")

        source_manifest.append({
            "filename": fname,
            "path": f_path,
            "rows_loaded": rows_read,
            "classes": class_dist,
        })
        loaded_dfs.append(df_file)

    # 3. Concatenate and Standardize
    combined_df = pd.concat(loaded_dfs, ignore_index=True)

    # 4. Standardize Target Labels & Binary Column
    combined_df["Label"] = combined_df["Label"].astype(str).str.strip()
    # Binary classification: BENIGN / Benign is 0, any attack is 1
    combined_df["Is_Attack"] = (combined_df["Label"].str.upper() != "BENIGN").astype(int)

    # 5. Handle Inf and NaN values on numeric feature columns
    feature_cols = [
        c for c in combined_df.columns
        if c.strip().lower() not in TARGET_AND_METADATA_COLS
    ]

    numeric_feature_cols = []
    for col in feature_cols:
        if not pd.api.types.is_numeric_dtype(combined_df[col]):
            converted = pd.to_numeric(combined_df[col], errors="coerce")
            if converted.notna().sum() > len(combined_df) * 0.5:
                combined_df[col] = converted
                numeric_feature_cols.append(col)
        else:
            numeric_feature_cols.append(col)

    print(f"\n⚙️ Cleaning {len(numeric_feature_cols)} numeric features:")
    # Replace +Inf and -Inf with NaN
    inf_count = np.isinf(combined_df[numeric_feature_cols]).sum().sum()
    print(f"   - Replaced {inf_count:,} infinite values with NaN")
    combined_df[numeric_feature_cols] = combined_df[numeric_feature_cols].replace([np.inf, -np.inf], np.nan)

    # Impute NaNs with column medians
    nan_count = combined_df[numeric_feature_cols].isna().sum().sum()
    print(f"   - Imputing {nan_count:,} missing values using feature medians...")
    medians = combined_df[numeric_feature_cols].median()
    combined_df[numeric_feature_cols] = combined_df[numeric_feature_cols].fillna(medians)

    # Assemble final cleaned dataset: features + Label + Is_Attack
    final_cols = numeric_feature_cols + ["Label", "Is_Attack"]
    cleaned_df = combined_df[final_cols].copy()

    # 6. Save Cleaned Dataset
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    cleaned_df.to_csv(output_path, index=False)
    print(f"\n💾 Saved cleaned dataset to: {output_path}")
    print(f"   Total records: {len(cleaned_df):,}")
    print(f"   Features:      {len(numeric_feature_cols)}")

    # 7. Create and Save Data Provenance Record
    overall_class_dist = cleaned_df["Label"].value_counts().to_dict()
    binary_dist = cleaned_df["Is_Attack"].value_counts().to_dict()
    provenance_data = {
        "provenance": provenance_type,
        "is_synthetic": is_synthetic,
        "warning": (
            "Model trained on synthetic data does NOT represent real-world performance."
            if is_synthetic else None
        ),
        "source_files": [m["filename"] for m in source_manifest],
        "source_manifest": source_manifest,
        "output_path": output_path,
        "total_records": len(cleaned_df),
        "feature_count": len(numeric_feature_cols),
        "feature_columns": numeric_feature_cols,
        "class_distribution": overall_class_dist,
        "binary_distribution": {
            "0 (BENIGN)": int(binary_dist.get(0, 0)),
            "1 (ATTACK)": int(binary_dist.get(1, 0)),
        },
        "train_medians": {col: float(val) for col, val in medians.to_dict().items()},
    }

    os.makedirs(os.path.dirname(provenance_path), exist_ok=True)
    with open(provenance_path, "w", encoding="utf-8") as f:
        json.dump(provenance_data, f, indent=2)
    print(f"📋 Data provenance record saved to: {provenance_path}")

    print("=" * 75)
    print(f"✅ PREPROCESSING COMPLETED SUCCESSFULLY")
    print(f"   Provenance: {provenance_type}")
    print(f"   Distribution: {overall_class_dist}")
    print("=" * 75)

    return provenance_data


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Preprocess authentic CIC-IDS2017 dataset")
    parser.add_argument("--raw-path", default="data/raw/cic-ids2017(real).csv", help="Path to raw CSV file or directory of CSVs")
    parser.add_argument("--output", default=DEFAULT_PROCESSED_CSV, help="Output cleaned CSV file path")
    parser.add_argument("--max-rows-per-file", type=int, default=50000, help="Max rows per file (None for all)")
    args = parser.parse_args()

    preprocess_dataset(
        raw_path=args.raw_path,
        output_path=args.output,
        max_rows_per_file=args.max_rows_per_file if args.max_rows_per_file > 0 else None,
    )
