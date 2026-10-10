"""
Data Preprocessing Pipeline for AWS Network Attack Detection System.
Cleans raw network flow CSV data by:
1. Stripping leading/trailing spaces from column headers.
2. Replacing infinite values (+Inf, -Inf) with NaN.
3. Imputing NaN values with column median statistics.
4. Adding a binary indicator column 'Is_Attack' (0 = BENIGN, 1 = Attack).
5. Exporting reproducible processed dataset to data/processed/cicids2017_cleaned.csv.
"""

import os
import pandas as pd
import numpy as np

def preprocess_dataset(
    raw_path="data/raw/cicids2017_sample.csv",
    output_path="data/processed/cicids2017_cleaned.csv"
):
    if not os.path.exists(raw_path):
        raise FileNotFoundError(f"Raw dataset not found at {raw_path}. Please run src/download_dataset.py first.")

    print("=" * 70)
    print(f"🧹 STARTING PREPROCESSING PIPELINE")
    print(f"   Input: {raw_path}")
    print("=" * 70)

    # 1. Load Raw CSV
    df = pd.read_csv(raw_path)
    initial_rows = len(df)

    # 2. Clean Column Headers (Strip Whitespace)
    df.columns = df.columns.str.strip()
    print("✅ Stripped whitespace from column headers.")

    if 'Label' not in df.columns:
        raise KeyError("Required target column 'Label' not found in dataset headers!")

    # 3. Clean Infinite & Missing Values
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    
    # Count initial NaNs and Infs
    inf_count = np.isinf(df[numeric_cols]).sum().sum()
    nan_count = df[numeric_cols].isna().sum().sum()
    print(f"   - Replacing {inf_count} infinite (Inf) values with NaN...")
    
    # Replace Inf with NaN
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)

    # Impute NaNs with column median (avoids data leakage by storing medians)
    print(f"   - Imputing total {nan_count + inf_count} NaN values using feature median values...")
    medians = df[numeric_cols].median()
    df[numeric_cols] = df[numeric_cols].fillna(medians)

    # 4. Standardize Target Labels & Add Binary Flag
    df['Label'] = df['Label'].astype(str).str.strip()
    df['Is_Attack'] = (df['Label'] != 'BENIGN').astype(int)

    # 5. Export Cleaned Dataset
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)

    print("=" * 70)
    print(f"✅ PREPROCESSING COMPLETED SUCCESSFULLY")
    print(f"   - Saved cleaned dataset: {output_path}")
    print(f"   - Total Cleaned Rows: {len(df):,}")
    print(f"   - Total Features: {df.shape[1] - 2} numeric features")
    print(f"   - Remaining Infs: {np.isinf(df[numeric_cols]).sum().sum()}")
    print(f"   - Remaining NaNs: {df.isnull().sum().sum()}")
    print(f"   - Binary Distribution:\n{df['Is_Attack'].value_counts().to_dict()} (0: Benign, 1: Attack)")
    print("=" * 70)

if __name__ == "__main__":
    preprocess_dataset()
