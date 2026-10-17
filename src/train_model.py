"""
Machine Learning Training Pipeline for AWS Network Attack Detection System
===========================================================================

Trains a Random Forest Classifier on cleaned network flow records.
Tracks and reports data provenance (authentic CIC-IDS2017 vs synthetic data),
evaluates classification metrics, and bundles provenance metadata with the saved model.
"""

import os
import sys
import json
import logging
from typing import Dict, Optional
import joblib
import pandas as pd
import numpy as np

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

DEFAULT_DATA_PATH = os.path.join("data", "processed", "cicids2017_cleaned.csv")
DEFAULT_PROVENANCE_PATH = os.path.join("data", "processed", "data_provenance.json")
DEFAULT_MODEL_PATH = os.path.join("models", "random_forest_model.joblib")


def train_and_evaluate(
    data_path: str = DEFAULT_DATA_PATH,
    provenance_path: str = DEFAULT_PROVENANCE_PATH,
    model_output_path: str = DEFAULT_MODEL_PATH,
    random_state: int = 42,
) -> Dict[str, any]:
    """
    Train Random Forest classifier with provenance reporting and evaluation.
    """
    if not os.path.exists(data_path):
        raise FileNotFoundError(
            f"Cleaned dataset missing at {data_path}. Run 'python src/preprocess.py' first."
        )

    # 1. Load Provenance Record
    provenance_info = {}
    if os.path.exists(provenance_path):
        try:
            with open(provenance_path, "r", encoding="utf-8") as f:
                provenance_info = json.load(f)
        except Exception as e:
            log.warning("Could not read provenance file: %s", e)

    is_synthetic = provenance_info.get("is_synthetic", "sample" in data_path.lower() or "synthetic" in data_path.lower())
    provenance_label = provenance_info.get("provenance", "SYNTHETIC-DEMO" if is_synthetic else "AUTHENTIC-CICIDS2017")
    source_files = provenance_info.get("source_files", [os.path.basename(data_path)])

    print("=" * 75)
    print("🤖 TRAINING RANDOM FOREST CLASSIFIER")
    print(f"   Dataset Path:     {data_path}")
    print(f"   Provenance:       {provenance_label}")
    print(f"   Is Synthetic:     {is_synthetic}")
    print(f"   Source Files:     {source_files}")
    if is_synthetic:
        print("⚠️  [NOTICE] Model is being trained on SYNTHETIC/DEMO data.")
        print("    Results from this run DO NOT represent real-world detection accuracy!")
    else:
        print("✅ [CONFIRMED] Model is being trained on AUTHENTIC CIC-IDS2017 data.")
    print("=" * 75)

    # 2. Load Dataset
    df = pd.read_csv(data_path, low_memory=False)

    # 3. Separate Features (X) and Target (y)
    ignore_cols = {"Label", "Is_Attack", "Source_File", "Unnamed: 0", "index"}
    feature_cols = [c for c in df.columns if c not in ignore_cols and pd.api.types.is_numeric_dtype(df[c])]

    if not feature_cols:
        raise ValueError("No valid numeric feature columns found in dataset!")

    X = df[feature_cols].copy()
    y = df["Is_Attack"].copy()

    print(f"   - Total Samples:      {len(df):,}")
    print(f"   - Feature Count:      {len(feature_cols)}")
    print(f"   - Target Distribution: {y.value_counts().to_dict()} (0: Benign, 1: Attack)")
    if "Label" in df.columns:
        print(f"   - Class Breakdown:    {df['Label'].value_counts().to_dict()}")

    # 4. Stratified Train / Test Split (80% Train, 20% Test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=random_state, stratify=y
    )
    print(f"   - Training Set:       {X_train.shape[0]:,} records")
    print(f"   - Test Set (Held-Out):{X_test.shape[0]:,} records")

    # 5. Train Random Forest Classifier
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        random_state=random_state,
        n_jobs=-1,
    )
    rf_model.fit(X_train, y_train)
    print("\n✅ Random Forest model training complete.")

    # 6. Evaluate on Held-Out Test Set
    y_pred = rf_model.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "=" * 75)
    print(f"📊 MODEL EVALUATION RESULTS (Held-Out Test Set)")
    print(f"   Provenance: {provenance_label}")
    print("=" * 75)
    print(f"   - ACCURACY:  {acc * 100:.2f}%")
    print(f"   - PRECISION: {prec * 100:.2f}%")
    print(f"   - RECALL:    {rec * 100:.2f}%")
    print(f"   - F1-SCORE:  {f1 * 100:.2f}%\n")

    print("📋 CLASSIFICATION REPORT:")
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"], zero_division=0))

    print("🧩 CONFUSION MATRIX:")
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    print(f"   True Negative  (Benign correctly identified): {tn:,}")
    print(f"   False Positive (Benign flagged as attack):    {fp:,}")
    print(f"   False Negative (Attack missed by model):       {fn:,}")
    print(f"   True Positive  (Attack correctly flagged):     {tp:,}")

    # 7. Feature Importance Analysis
    importances = rf_model.feature_importances_
    indices = np.argsort(importances)[::-1][:10]

    print("\n🔥 TOP 10 MOST INFLUENTIAL FEATURES:")
    for rank, idx in enumerate(indices, 1):
        print(f"   {rank}. {feature_cols[idx]:<35} Importance: {importances[idx]:.4f}")

    # 8. Save Model and Comprehensive Metadata Bundle
    os.makedirs(os.path.dirname(model_output_path), exist_ok=True)
    model_bundle = {
        "model": rf_model,
        "feature_names": feature_cols,
        "provenance": provenance_label,
        "is_synthetic": is_synthetic,
        "source_files": source_files,
        "metrics": {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
            "test_samples": len(y_test),
        },
    }
    joblib.dump(model_bundle, model_output_path)
    print(f"\n💾 Model bundle saved to: {model_output_path}")
    print("=" * 75)

    return model_bundle


if __name__ == "__main__":
    train_and_evaluate()
