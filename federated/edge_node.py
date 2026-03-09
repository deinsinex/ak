import xgboost as xgb
import pandas as pd
import numpy as np
import os


class EdgeNode:

    def __init__(self, node_id, dataset_path):

        self.node_id = node_id
        self.dataset_path = dataset_path
        self.model = None


    def load_data(self):

        print(f"[{self.node_id}] Loading local dataset...")

        if not os.path.exists(self.dataset_path):
            raise FileNotFoundError(f"Dataset not found: {self.dataset_path}")

        df = pd.read_csv(self.dataset_path)

        # Convert labels
        if "label1" not in df.columns:
            raise ValueError("Dataset must contain 'label1' column")

        df["target"] = df["label1"].apply(
            lambda x: 1 if str(x).lower() == "attack" else 0
        )

        df = df.select_dtypes(include=[np.number])

        if "target" not in df.columns:
            raise ValueError("Target column missing after preprocessing")

        y = df["target"]
        X = df.drop(columns=["target"])

        return X, y


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

        for i, value in enumerate(importances):

            weights[f"feature_{i}"] = float(value)

        return weights
