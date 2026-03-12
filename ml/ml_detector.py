import os
import json
import joblib
import pandas as pd


MODEL_PATH = "training/firewall_xgboost.pkl"
METADATA_PATH = "training/model_metadata.json"


class MLDetector:

    def __init__(self):

        self.model = None
        self.feature_names = []

        self._load_model()

    def _load_model(self):

        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"Missing model file: {MODEL_PATH}")

        if not os.path.exists(METADATA_PATH):
            raise FileNotFoundError(f"Missing metadata file: {METADATA_PATH}")

        self.model = joblib.load(MODEL_PATH)

        with open(METADATA_PATH, "r") as f:
            metadata = json.load(f)

        self.feature_names = metadata.get("feature_names", [])

        if not self.feature_names:
            raise ValueError("model_metadata.json missing feature_names")

        print(f"[ML] Loaded model with expected features: {len(self.feature_names)}")

    def analyze(self, features: dict):

        if not isinstance(features, dict):
            return {
                "is_attack": False,
                "attack_probability": 0.0,
                "reason": "invalid_features"
            }

        aligned = {
            name: float(features.get(name, 0.0))
            for name in self.feature_names
        }

        X = pd.DataFrame([aligned], columns=self.feature_names)

        proba = self.model.predict_proba(X)[0][1]
        is_attack = bool(proba >= 0.5)

        return {
            "is_attack": is_attack,
            "attack_probability": float(proba),
            "reason": "ml_inference"
        }
