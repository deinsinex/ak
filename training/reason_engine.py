import shap
import joblib
import pandas as pd
import numpy as np
import json
import os


print("Loading firewall brain...")

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

explainer = shap.TreeExplainer(model)


def explain_event(event_df):

    # keep only numeric columns
    event_df = event_df.select_dtypes(include=[np.number])

    # enforce correct feature order
    event_df = event_df[feature_names]

    shap_values = explainer(event_df)

    # handle classification models returning list
    if isinstance(shap_values.values, list):
        values = shap_values.values[1][0]
    else:
        values = shap_values.values[0]

    contributions = list(zip(feature_names, values))

    contributions = sorted(
        contributions,
        key=lambda x: abs(x[1]),
        reverse=True
    )

    top_reasons = contributions[:5]

    print("\n🚨 BLOCK REASONS:")

    for feature, impact in top_reasons:
        direction = "ATTACK ↑" if impact > 0 else "BENIGN ↓"
        print(f"{feature} → {round(float(impact),3)} ({direction})")

    return top_reasons
