"""
Dataset Inspection Script for AWS Network Attack Detection System.
Analyzes raw CIC-IDS2017 sample CSV for missing values, infinite values,
data types, column name formatting issues, and label distribution.
"""

import os
import pandas as pd
import numpy as np

def inspect_dataset(file_path="data/raw/cicids2017_sample.csv"):
    if not os.path.exists(file_path):
        print(f"❌ Error: Dataset file not found at {file_path}")
        return

    print("=" * 70)
    print(f"🔍 INSPECTING DATASET: {file_path}")
    print("=" * 70)

    # Read CSV
    df = pd.read_csv(file_path)

    # 1. Basic Shape
    print(f"\n1. DATASET SHAPE:")
    print(f"   - Total Rows: {df.shape[0]:,}")
    print(f"   - Total Columns: {df.shape[1]}")

    # 2. Column Names & Whitespace Check
    whitespace_cols = [c for c in df.columns if c.startswith(' ') or c.endswith(' ')]
    print(f"\n2. COLUMN NAME HEALTH:")
    print(f"   - Columns with leading/trailing spaces: {len(whitespace_cols)}")
    if whitespace_cols:
        print(f"     Example messy column names: {whitespace_cols[:5]}")

    # 3. Label Column Identification & Class Distribution
    # Look for 'Label' or ' Label'
    label_col = [c for c in df.columns if 'label' in c.lower()]
    if label_col:
        target_col = label_col[0]
        print(f"\n3. TARGET CLASS DISTRIBUTION (Column: '{target_col}'):")
        counts = df[target_col].value_counts()
        percentages = df[target_col].value_counts(normalize=True) * 100
        dist_df = pd.DataFrame({'Count': counts, 'Percentage (%)': percentages.round(2)})
        print(dist_df.to_string())
    else:
        print("\n❌ Warning: No 'Label' column found!")

    # 4. Missing Values & Infinite Values Check
    numeric_df = df.select_dtypes(include=[np.number])
    null_counts = df.isnull().sum()
    null_cols = null_counts[null_counts > 0]

    # Inf check
    inf_counts = np.isinf(numeric_df).sum()
    inf_cols = inf_counts[inf_counts > 0]

    print(f"\n4. DATA QUALITY & ANOMALIES:")
    print(f"   - Total missing (NaN/null) values across dataset: {null_counts.sum()}")
    if len(null_cols) > 0:
        print(f"     Columns with NaNs: {dict(null_cols)}")

    print(f"   - Total infinite (Inf / -Inf) values: {inf_counts.sum()}")
    if len(inf_cols) > 0:
        print(f"     Columns with Infs: {dict(inf_cols)}")

    print("\n" + "=" * 70)

if __name__ == "__main__":
    inspect_dataset()
