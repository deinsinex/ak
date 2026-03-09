import shap
import joblib
import pandas as pd
import numpy as np
import json
import os


print("Loading model...")

MODEL_PATH = "firewall_xgboost.pkl"
METADATA_PATH = "model_metadata.json"

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

if not os.path.exists(METADATA_PATH):
    raise FileNotFoundError(f"Metadata not found: {METADATA_PATH}")

model = joblib.load(MODEL_PATH)

with open(METADATA_PATH) as f:
    metadata = json.load(f)

feature_names = metadata["feature_names"]


print("Preparing sample data...")

attack = pd.read_csv("../datasets/attack_data/attack_samples_5sec.csv")
benign = pd.read_csv("../datasets/benign_data/benign_samples_5sec.csv")

df = pd.concat([attack, benign], ignore_index=True)


df['target'] = df['label1'].apply(
    lambda x: 1 if str(x).lower() == "attack" else 0
)


drop_columns = [
    col for col in df.columns if
    (
        "mac" in col or
        "ip" in col or
        "port" in col or
        "protocol" in col or
        "timestamp" in col or
        "device" in col or
        "label" in col
    )
]

df = df.drop(columns=drop_columns, errors='ignore')
df = df.select_dtypes(include=[np.number])


X = df.drop("target", axis=1)

# ensure feature order matches training
X = X[feature_names]


print("Creating SHAP explainer...")

explainer = shap.TreeExplainer(model)

sample = X.iloc[0:1]

shap_values = explainer(sample)


print("\n🔥 WHY DID THE MODEL DECIDE THIS?\n")

for feature, value in zip(feature_names, shap_values.values[0]):

    if abs(value) > 0.01:
        print(feature, "→ influence:", round(value, 4))
