import joblib
import numpy as np
import json
import shap
import os


MODEL_PATH = "training/firewall_xgboost.pkl"
METADATA_PATH = "training/model_metadata.json"


class MLDetector:

    def __init__(self):

        print("🤖 Loading ML detection engine...")

        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

        if not os.path.exists(METADATA_PATH):
            raise FileNotFoundError(f"Metadata not found: {METADATA_PATH}")

        self.model = joblib.load(MODEL_PATH)

        with open(METADATA_PATH) as f:
            metadata = json.load(f)

        self.feature_names = metadata["feature_names"]

        print("✅ ML model loaded")
        print(f"Expected features: {len(self.feature_names)}")

        self.explainer = shap.TreeExplainer(self.model)


    def prepare_features(self, features_dict):

        vector = []

        for name in self.feature_names:
            value = features_dict.get(name, 0)
            vector.append(value)

        return np.array(vector, dtype=float).reshape(1, -1)


    def predict(self, features):

        X = self.prepare_features(features)

        try:
            probability = self.model.predict_proba(X)[0][1]
        except Exception:
            probability = 0.0

        return float(probability)


    def explain(self, features):

        X = self.prepare_features(features)

        shap_values = self.explainer.shap_values(X)

        if isinstance(shap_values, list):
            shap_values = shap_values[1]

        explanation = {}

        for i, name in enumerate(self.feature_names):

            influence = float(shap_values[0][i])

            if abs(influence) > 0.01:
                explanation[name] = influence

        return explanation


    def analyze(self, features):

        probability = self.predict(features)

        result = {
            "attack_probability": probability,
            "is_attack": probability > 0.7
        }

        if result["is_attack"]:

            explanation = self.explain(features)

            result["reason"] = explanation

        return result
