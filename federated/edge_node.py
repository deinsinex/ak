import xgboost as xgb
import pandas as pd
import numpy as np
import os
import json


MODEL_METADATA_FILE = "training/model_metadata.json"


class EdgeNode:

    def __init__(self, node_id, dataset_path):

        self.node_id = node_id
        self.dataset_path = dataset_path
        self.model = None
        self.feature_names = self._load_feature_names()

    def _load_feature_names(self):

        if not os.path.exists(MODEL_METADATA_FILE):
            raise FileNotFoundError(f"Missing model metadata: {MODEL_METADATA_FILE}")

        with open(MODEL_METADATA_FILE, "r") as f:
            data = json.load(f)

        feature_names = data.get("feature_names")

        if not feature_names or not isinstance(feature_names, list):
            raise ValueError("Invalid model_metadata.json: missing feature_names")

        return feature_names

    def load_data(self):

        print(f"[{self.node_id}] Loading local dataset...")

        if not os.path.exists(self.dataset_path):
            raise FileNotFoundError(f"Dataset not found: {self.dataset_path}")

        df = pd.read_csv(self.dataset_path)

        # -----------------------------
        # Build target from label1
        # -----------------------------
        if "label1" not in df.columns:
            raise ValueError("Dataset must contain 'label1' column")

        df["target"] = df["label1"].apply(
            lambda x: 1 if str(x).strip().lower() == "attack" else 0
        ).astype(int)

        # -----------------------------
        # Strict 51-feature alignment
        # -----------------------------
        aligned = pd.DataFrame()

        for feature in self.feature_names:

            if feature in df.columns:
                aligned[feature] = pd.to_numeric(df[feature], errors="coerce").fillna(0.0)
            else:
                aligned[feature] = 0.0

        y = df["target"]

        if aligned.empty:
            raise ValueError("Aligned feature matrix is empty")

        print(f"[{self.node_id}] Exact metadata features used: {len(self.feature_names)}")
        print(f"[{self.node_id}] Samples loaded: {len(aligned)}")

        return aligned, y


    def train_local_model(self):

        X, y = self.load_data()

        print(f"[{self.node_id}] Training local model...")

        self.model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="logloss",
            random_state=42
        )

        self.model.fit(X, y)

        print(f"[{self.node_id}] Training complete.")


    def export_weights(self):

        if self.model is None:
            raise ValueError("Model not trained yet.")

        print(f"[{self.node_id}] Exporting model weights...")

        importances = self.model.feature_importances_

        weights = {}

        for feature_name, value in zip(self.feature_names, importances):
            weights[feature_name] = float(value)

        return weights
