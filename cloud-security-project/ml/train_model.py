"""
train_model.py
------------------------------------------------
Trains a RandomForestClassifier on a real network
intrusion dataset (CICIDS2017 / CSE-CIC-IDS2018 /
NSL-KDD, or similar) for future ML-powered threat
detection.

USAGE:
    1. Place a CSV file inside the /datasets folder.
    2. Run:  py ml/train_model.py --file datasets/your_file.csv
       (or just run with no --file to auto-pick the
        first CSV found in /datasets)

This script is NOT required for the dashboard to work.
The dashboard runs fine using the 4 fixed demo incidents
even if no model has ever been trained.
------------------------------------------------
"""

import os
import sys
import argparse
from datetime import UTC, datetime

import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score, f1_score, roc_curve, auc

# Allow running this file directly (python ml/train_model.py)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.preprocess import clean_dataframe, find_label_column, prepare_features_for_training, scale_features
from database.db import init_db, log_audit_event, save_model_version

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
MODELS_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODELS_DIR, "rf_model.pkl")


def find_default_csv():
    """Find the first .csv file inside /datasets, if any."""
    if not os.path.isdir(DATASETS_DIR):
        return None
    for fname in os.listdir(DATASETS_DIR):
        if fname.lower().endswith(".csv"):
            return os.path.join(DATASETS_DIR, fname)
    return None


def train(csv_path):
    init_db()
    log_audit_event(
        "system",
        "model_training_started",
        "ml_training",
        f"Training started for {os.path.basename(csv_path)}",
        "local",
    )
    print(f"[INFO] Loading dataset: {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False)

    print(f"[INFO] Raw shape: {df.shape}")
    df = clean_dataframe(df)
    print(f"[INFO] Cleaned shape: {df.shape}")

    label_column = find_label_column(df)
    if label_column is None:
        print("[ERROR] Could not find a 'Label' or 'label' column in the dataset.")
        sys.exit(1)

    X, y = prepare_features_for_training(df, label_column)

    if X.shape[1] == 0:
        print("[ERROR] No numeric feature columns found after cleaning.")
        sys.exit(1)

    # Encode text labels (e.g. "BENIGN", "DDoS") into numbers
    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )
    X_train_scaled, X_test_scaled, scaler = scale_features(X_train, X_test)

    print("[INFO] Training RandomForestClassifier...")
    model = RandomForestClassifier(
        n_estimators=100, max_depth=None, random_state=42, n_jobs=-1
    )
    model.fit(X_train_scaled, y_train)

    y_pred = model.predict(X_test_scaled)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    recall = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)
    matrix = confusion_matrix(y_test, y_pred).tolist()
    roc_data = {}
    if hasattr(model, "predict_proba") and len(encoder.classes_) == 2:
        y_score = model.predict_proba(X_test_scaled)[:, 1]
        fpr, tpr, _ = roc_curve(y_test, y_score)
        roc_data = {"fpr": fpr.tolist(), "tpr": tpr.tolist(), "auc": float(auc(fpr, tpr))}

    version = datetime.now(UTC).strftime("rf-%Y%m%d%H%M%S")
    metrics = {
        "version": version,
        "model_path": MODEL_PATH,
        "dataset_name": os.path.basename(csv_path),
        "accuracy": round(float(accuracy), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4),
        "confusion_matrix": matrix,
        "roc_curve": roc_data,
        "training_history": {
            "rows": int(df.shape[0]),
            "features": int(X.shape[1]),
            "classes": list(encoder.classes_),
            "trained_at": version,
        },
    }

    print("\n===== Model Evaluation =====")
    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1-score : {f1:.4f}")
    print("=============================\n")

    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "label_encoder": encoder,
            "feature_columns": list(X.columns),
            "scaler": scaler,
            "metrics": metrics,
            "version": version,
        },
        MODEL_PATH,
    )
    save_model_version(metrics)
    print(f"[INFO] Model saved to: {MODEL_PATH}")
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train RandomForest threat detection model.")
    parser.add_argument("--file", type=str, default=None, help="Path to training CSV file.")
    args = parser.parse_args()

    csv_path = args.file or find_default_csv()

    if not csv_path or not os.path.exists(csv_path):
        print("[ERROR] No dataset found. Place a CSV file inside the 'datasets' folder,")
        print("        or pass one explicitly with --file path/to/file.csv")
        print("        Suggested datasets: CICIDS2017, CSE-CIC-IDS2018, NSL-KDD")
        sys.exit(1)

    train(csv_path)
