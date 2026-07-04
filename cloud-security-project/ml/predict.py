"""
predict.py
------------------------------------------------
Loads the trained RandomForest model (models/rf_model.pkl)
if it exists, and exposes a simple predict() function.

If no model has been trained yet, this module returns a
graceful "model not available" message instead of crashing,
so the dashboard keeps working even before training.
------------------------------------------------
"""

import os
import joblib
import pandas as pd
import math

from ml.preprocess import dataframe_to_feature_rows

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "rf_model.pkl")

_model_bundle = None
_model_loaded_attempted = False


def _safe_feature_value(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0
    if not math.isfinite(number):
        return 0
    return max(min(number, 1_000_000_000), -1_000_000_000)


def _load_model():
    """Load the model bundle from disk once, and cache it."""
    global _model_bundle, _model_loaded_attempted

    if _model_loaded_attempted and _model_bundle is not None:
        return _model_bundle
    if _model_loaded_attempted and _model_bundle is None and not os.path.exists(MODEL_PATH):
        return None

    _model_loaded_attempted = True

    if os.path.exists(MODEL_PATH):
        try:
            _model_bundle = joblib.load(MODEL_PATH)
            print("[INFO] ML model loaded successfully.")
        except Exception as e:
            print(f"[WARN] Failed to load model: {e}")
            _model_bundle = None
    else:
        print("[INFO] No trained model found. Run ml/train_model.py to train one.")
        _model_bundle = None

    return _model_bundle


def is_model_available():
    """Check whether a trained model is currently available."""
    return _load_model() is not None


def predict(features: dict):
    """
    Predict the attack label for a given feature dictionary.

    Args:
        features (dict): feature_name -> value

    Returns:
        dict: {
            "available": bool,
            "prediction": str or None,
            "message": str
        }
    """
    bundle = _load_model()

    if bundle is None:
        return {
            "available": False,
            "prediction": None,
            "message": (
                "ML model not trained yet. The dashboard is running in "
                "rule-based mode using the built-in risk engine. "
                "Run 'py ml/train_model.py' after adding a dataset to "
                "the /datasets folder to enable ML predictions."
            ),
        }

    try:
        model = bundle["model"]
        encoder = bundle["label_encoder"]
        feature_columns = bundle["feature_columns"]
        scaler = bundle.get("scaler")

        row = pd.DataFrame(
            [[_safe_feature_value(features.get(col, 0)) for col in feature_columns]],
            columns=feature_columns,
        )
        if scaler is not None:
            row = scaler.transform(row)
        pred_encoded = model.predict(row)[0]
        pred_label = encoder.inverse_transform([pred_encoded])[0]
        confidence = 80
        if hasattr(model, "predict_proba"):
            confidence = round(float(max(model.predict_proba(row)[0])) * 100, 2)

        return {
            "available": True,
            "prediction": str(pred_label),
            "confidence": confidence,
            "message": "Prediction generated using the trained RandomForest model.",
        }
    except Exception:
        return {
            "available": False,
            "prediction": None,
            "message": "Prediction failed safely. Please verify the model and feature format.",
        }


def get_model_metadata():
    bundle = _load_model()
    if bundle is None:
        return None
    return bundle.get("metrics") or {"version": bundle.get("version", "unknown")}


def predict_csv(csv_path, limit=25):
    bundle = _load_model()
    if bundle is None:
        return []
    try:
        df = pd.read_csv(csv_path, low_memory=False)
        rows = dataframe_to_feature_rows(df.head(limit), bundle["feature_columns"])
    except Exception:
        return []
    results = []
    for index, row in enumerate(rows, start=1):
        result = predict(row)
        result["row"] = index
        results.append(result)
    return results


def extract_pcap_features(pcap_path, limit=25):
    try:
        from scapy.all import rdpcap, IP, TCP, UDP
    except Exception:
        return []

    try:
        packets = rdpcap(pcap_path)
    except Exception:
        return []
    rows = []
    for packet in packets[:limit]:
        if IP not in packet:
            continue
        rows.append(
            {
                "Source Port": int(packet[TCP].sport) if TCP in packet else int(packet[UDP].sport) if UDP in packet else 0,
                "Destination Port": int(packet[TCP].dport) if TCP in packet else int(packet[UDP].dport) if UDP in packet else 0,
                "Protocol": int(packet[IP].proto),
                "Flow Duration": 0,
                "Total Fwd Packets": 1,
                "Total Backward Packets": 0,
                "Total Length of Fwd Packets": int(len(packet)),
                "Total Length of Bwd Packets": 0,
            }
        )
    return rows


def predict_pcap(pcap_path, limit=25):
    rows = extract_pcap_features(pcap_path, limit=limit)
    results = []
    for index, row in enumerate(rows, start=1):
        result = predict(row)
        result["row"] = index
        results.append(result)
    return results


if __name__ == "__main__":
    print(predict({}))
