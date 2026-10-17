"""
Dataset Inspection Script for AWS Network Attack Detection System
==================================================================

Analyzes either a single CSV file or a directory of CSV files (e.g., data/raw/cicids2017).
Checks:
1. File discovery and file sizes
2. Data provenance (authentic vs synthetic)
3. Column name formatting and whitespace health
4. Target 'Label' column validation & multi-class distribution
5. Missing (NaN) and Infinite (+/-Inf) values
"""

import os
import sys
from pathlib import Path
from typing import List, Optional
import pandas as pd
import numpy as np

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def inspect_single_csv(file_path: str, max_sample_rows: int = 5000) -> dict:
    """Inspect an individual CSV dataset file."""
    if not os.path.exists(file_path):
        print(f"[ERROR] Dataset file not found at {file_path}")
        return {"error": "File not found"}

    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
    is_synthetic = "synthetic" in file_path.lower() or "sample" in file_path.lower()
    provenance = "SYNTHETIC-DEMO" if is_synthetic else "AUTHENTIC-CICIDS2017"

    print("\n" + "-" * 70)
    print(f"FILE:       {os.path.abspath(file_path)}")
    print(f"Size:       {file_size_mb:.2f} MB")
    print(f"Provenance: {provenance}")
    print("-" * 70)

    try:
        df = pd.read_csv(file_path, nrows=max_sample_rows, low_memory=False)
    except UnicodeDecodeError:
        df = pd.read_csv(file_path, nrows=max_sample_rows, encoding="latin-1", low_memory=False)

    print(f"1. SHAPE (Sampled first {len(df):,} rows):")
    print(f"   - Sample Rows:   {df.shape[0]:,}")
    print(f"   - Total Columns: {df.shape[1]}")

    # Whitespace check
    whitespace_cols = [c for c in df.columns if str(c).startswith(" ") or str(c).endswith(" ")]
    print(f"\n2. COLUMN NAME HEALTH:")
    print(f"   - Columns with leading/trailing spaces: {len(whitespace_cols)}")
    if whitespace_cols:
        print(f"     Example whitespace columns: {[repr(c) for c in whitespace_cols[:4]]}")

    clean_df = df.copy()
    clean_df.columns = clean_df.columns.str.strip()

    # Target class check
    label_cols = [c for c in clean_df.columns if c.lower() in ("label", "class")]
    if label_cols:
        target_col = label_cols[0]
        print(f"\n3. TARGET CLASS DISTRIBUTION (Column: '{target_col}'):")
        counts = clean_df[target_col].astype(str).str.strip().value_counts()
        percentages = clean_df[target_col].astype(str).str.strip().value_counts(normalize=True) * 100
        dist_df = pd.DataFrame({"Count": counts, "Percentage (%)": percentages.round(2)})
        print(dist_df.to_string())
    else:
        print("\n[WARN] No 'Label' column found!")

    # Missing & Infinite Values
    numeric_df = clean_df.select_dtypes(include=[np.number])
    null_counts = clean_df.isnull().sum()
    inf_counts = np.isinf(numeric_df).sum() if not numeric_df.empty else pd.Series(0)

    total_nulls = int(null_counts.sum())
    total_infs = int(inf_counts.sum()) if not numeric_df.empty else 0

    print(f"\n4. DATA QUALITY & ANOMALIES:")
    print(f"   - Total NaN/null values in sample: {total_nulls}")
    print(f"   - Total Infinite (+/-Inf) values: {total_infs}")

    return {
        "file": file_path,
        "size_mb": round(file_size_mb, 2),
        "provenance": provenance,
        "columns": clean_df.shape[1],
        "has_label": len(label_cols) > 0,
        "sample_classes": clean_df[label_cols[0]].value_counts().to_dict() if label_cols else {},
    }


def inspect_dataset(target: str = "data/raw/cicids2017"):
    """
    Inspect either a single CSV file or an entire directory of CSV files.
    """
    if not os.path.exists(target):
        if os.path.exists("data/raw/cicids2017_sample.csv"):
            print(f"[WARN] Target '{target}' not found. Falling back to data/raw/cicids2017_sample.csv")
            target = "data/raw/cicids2017_sample.csv"
        else:
            print(f"[ERROR] Target path not found: {target}")
            return

    print("=" * 70)
    print(f"[INSPECT] INSPECTING DATASET SOURCE: {target}")
    print("=" * 70)

    if os.path.isfile(target):
        inspect_single_csv(target)
    elif os.path.isdir(target):
        csv_files = list(Path(target).glob("*.csv"))
        if not csv_files:
            print(f"[WARN] No CSV files found in directory: {target}")
            return

        print(f"Discovered {len(csv_files)} CSV files in {target}:")
        results = []
        for csv_path in sorted(csv_files):
            res = inspect_single_csv(str(csv_path))
            results.append(res)

        print("\n" + "=" * 70)
        print("SUMMARY ACROSS ALL DISCOVERED FILES:")
        print("=" * 70)
        valid_count = sum(1 for r in results if r.get("has_label"))
        total_mb = sum(r.get("size_mb", 0) for r in results)
        print(f"   Total CSV Files:     {len(results)}")
        print(f"   Valid Flow Datasets: {valid_count}/{len(results)}")
        print(f"   Total Raw Size:      {total_mb:.2f} MB")
        print("=" * 70)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Inspect raw or processed network attack datasets")
    parser.add_argument("--path", default="data/raw/cicids2017", help="Path to CSV file or directory of CSVs")
    args = parser.parse_args()
    inspect_dataset(args.path)
