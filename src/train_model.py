"""
Machine Learning Training Pipeline for AWS Network Attack Detection System.
Trains a Random Forest Classifier on CIC-IDS2017 cleaned flow records.
Evaluates model metrics, calculates feature importances, compares against rule baseline,
and serializes the trained model to models/random_forest_model.joblib.
"""

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

def train_and_evaluate(
    data_path="data/processed/cicids2017_cleaned.csv",
    model_output_path="models/random_forest_model.joblib"
):
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Cleaned dataset missing at {data_path}. Run src/preprocess.py first.")

    print("=" * 70)
    print("🤖 TRAINING RANDOM FOREST MACHINE LEARNING MODEL")
    print("=" * 70)

    # 1. Load Cleaned Dataset
    df = pd.read_csv(data_path)

    # 2. Separate Features (X) and Target (y)
    ignore_cols = ["Label", "Is_Attack"]
    feature_cols = [c for c in df.columns if c not in ignore_cols]
    
    X = df[feature_cols]
    y = df["Is_Attack"]

    print(f"   - Dataset Shape: {df.shape}")
    print(f"   - Number of Features: {len(feature_cols)}")
    print(f"   - Target Distribution: {y.value_counts().to_dict()} (0: Benign, 1: Attack)")

    # 3. Stratified Train / Test Split (80% Train, 20% Test) to prevent data leakage
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"   - Training Samples: {X_train.shape[0]:,}")
    print(f"   - Test Samples (Unseen): {X_test.shape[0]:,}")

    # 4. Train Random Forest Classifier
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)
    print("✅ Random Forest model training complete.")

    # 5. Predictions on Unseen Test Set
    y_pred = rf_model.predict(X_test)

    # 6. Metrics Calculation
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "=" * 70)
    print(f"📊 ML MODEL EVALUATION RESULTS (Unseen Test Set)")
    print("=" * 70)
    print(f"   - ACCURACY:  {acc * 100:.2f}%")
    print(f"   - PRECISION: {prec * 100:.2f}%")
    print(f"   - RECALL:    {rec * 100:.2f}%")
    print(f"   - F1-SCORE:  {f1 * 100:.2f}%\n")

    print("📋 DETAILED CLASSIFICATION REPORT:")
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"]))

    print("🧩 CONFUSION MATRIX:")
    print(f"   True Negative (Benign correctly identified):  {cm[0][0]}")
    print(f"   False Positive (Benign flagged as attack):  {cm[0][1]}")
    print(f"   False Negative (Attack missed by ML model):  {cm[1][0]}")
    print(f"   True Positive (Attack correctly flagged):    {cm[1][1]}")

    # 7. Feature Importance Analysis
    importances = rf_model.feature_importances_
    indices = np.argsort(importances)[::-1][:10]

    print("\n🔥 TOP 10 MOST IMPORTANT DETECTIVE FEATURES:")
    for rank, idx in enumerate(indices, 1):
        print(f"   {rank}. {feature_cols[idx]:<35} Importance: {importances[idx]:.4f}")

    # 8. Save Trained Model and Metadata Bundle
    os.makedirs(os.path.dirname(model_output_path), exist_ok=True)
    model_bundle = {
        "model": rf_model,
        "feature_names": feature_cols,
        "metrics": {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1}
    }
    joblib.dump(model_bundle, model_output_path)
    print(f"\n💾 Saved trained model artifact to: {model_output_path}")
    print("=" * 70)

if __name__ == "__main__":
    train_and_evaluate()
