import pandas as pd
import numpy as np
import os
import json

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from xgboost import XGBClassifier
import joblib


print("\n🔥 Aegis Firewall ML Training Starting...\n")


# ==============================
# LOAD DATASETS
# ==============================

print("Loading datasets...")

attack_path = "../datasets/attack_data/attack_samples_5sec.csv"
benign_path = "../datasets/benign_data/benign_samples_5sec.csv"

if not os.path.exists(attack_path):
    raise FileNotFoundError(f"Attack dataset not found: {attack_path}")

if not os.path.exists(benign_path):
    raise FileNotFoundError(f"Benign dataset not found: {benign_path}")

attack = pd.read_csv(attack_path)
benign = pd.read_csv(benign_path)

df = pd.concat([attack, benign], ignore_index=True)

print("Dataset size:", df.shape)


# ==============================
# CREATE TARGET LABEL
# ==============================

if "label1" not in df.columns:
    raise ValueError("Dataset must contain 'label1' column")

df["target"] = df["label1"].apply(
    lambda x: 1 if str(x).lower() == "attack" else 0
)


# ==============================
# REMOVE NON-LEARNING FEATURES
# ==============================

drop_columns = [
    col for col in df.columns
    if (
        "mac" in col
        or "ip" in col
        or "port" in col
        or "protocol" in col
        or "timestamp" in col
        or "device" in col
        or "label" in col
    )
]

df = df.drop(columns=drop_columns, errors="ignore")


# ==============================
# KEEP NUMERIC FEATURES ONLY
# ==============================

df = df.select_dtypes(include=[np.number])

print("Features remaining:", df.shape)


# ==============================
# SPLIT FEATURES / LABEL
# ==============================

if "target" not in df.columns:
    raise ValueError("Target column missing after preprocessing")

X = df.drop("target", axis=1)
y = df["target"]

feature_names = list(X.columns)

print("Feature count:", len(feature_names))


# ==============================
# TRAIN TEST SPLIT
# ==============================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


# ==============================
# TRAIN MODEL
# ==============================

print("\nTraining XGBoost model...\n")

model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    tree_method="hist",
    eval_metric="logloss",
    random_state=42
)

model.fit(X_train, y_train)


# ==============================
# MODEL EVALUATION
# ==============================

pred = model.predict(X_test)

print("\n📊 MODEL PERFORMANCE\n")

print(classification_report(y_test, pred))


# ==============================
# SAVE MODEL
# ==============================

model_path = "firewall_xgboost.pkl"

joblib.dump(model, model_path)


# ==============================
# SAVE METADATA
# ==============================

metadata = {
    "feature_names": feature_names,
    "feature_count": len(feature_names),
    "model_type": "XGBoost",
    "dataset": "CIC IIoT 2025"
}

metadata_path = "model_metadata.json"

with open(metadata_path, "w") as f:
    json.dump(metadata, f, indent=4)


print("\n✅ Model saved:", model_path)
print("✅ Metadata saved:", metadata_path)

print("\n🚀 Training complete.\n")
