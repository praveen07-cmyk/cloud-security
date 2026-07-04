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

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "rf_model.pkl")

_model_bundle = None
_model_loaded_attempted = False


def _load_model():
    """Load the model bundle from disk once, and cache it."""
    global _model_bundle, _model_loaded_attempted

    if _model_loaded_attempted:
        return _model_bundle

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

        row = [[features.get(col, 0) for col in feature_columns]]
        pred_encoded = model.predict(row)[0]
        pred_label = encoder.inverse_transform([pred_encoded])[0]

        return {
            "available": True,
            "prediction": str(pred_label),
            "message": "Prediction generated using the trained RandomForest model.",
        }
    except Exception as e:
        return {
            "available": False,
            "prediction": None,
            "message": f"Prediction failed: {e}",
        }


if __name__ == "__main__":
    print(predict({}))
