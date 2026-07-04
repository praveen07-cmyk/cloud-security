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

import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Allow running this file directly (python ml/train_model.py)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.preprocess import clean_dataframe, find_label_column, split_features_labels

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
    print(f"[INFO] Loading dataset: {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False)

    print(f"[INFO] Raw shape: {df.shape}")
    df = clean_dataframe(df)
    print(f"[INFO] Cleaned shape: {df.shape}")

    label_column = find_label_column(df)
    if label_column is None:
        print("[ERROR] Could not find a 'Label' or 'label' column in the dataset.")
        sys.exit(1)

    X, y = split_features_labels(df, label_column)

    if X.shape[1] == 0:
        print("[ERROR] No numeric feature columns found after cleaning.")
        sys.exit(1)

    # Encode text labels (e.g. "BENIGN", "DDoS") into numbers
    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )

    print("[INFO] Training RandomForestClassifier...")
    model = RandomForestClassifier(
        n_estimators=100, max_depth=None, random_state=42, n_jobs=-1
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    recall = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

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
        },
        MODEL_PATH,
    )
    print(f"[INFO] Model saved to: {MODEL_PATH}")


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
