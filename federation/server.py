from flask import Flask, request, jsonify
import numpy as np
import json
import os
import threading

from federation.crypto_utils import verify_weights

app = Flask(__name__)

model_pool = []
global_model = None
model_version = 0

MIN_CLIENTS = 3

pool_lock = threading.Lock()

MODEL_FILE = "federation/global_model.json"


def save_global_model(model):

    os.makedirs("federation", exist_ok=True)

    with open(MODEL_FILE, "w") as f:
        json.dump(model, f)


def load_global_model():

    global global_model
    global model_version

    if os.path.exists(MODEL_FILE):

        with open(MODEL_FILE, "r") as f:
            global_model = json.load(f)

        model_version = 1
        print("Loaded existing global model from disk.")


def aggregate_models(models):

    keys = models[0].keys()
    aggregated = {}

    for key in keys:

        values = []

        for model in models:

            if key not in model:
                continue

            try:
                value = float(model[key])
            except Exception:
                continue

            if abs(value) > 1e6:
                continue

            values.append(value)

        if values:
            aggregated[key] = float(np.mean(values))

    return aggregated


@app.route("/upload_weights", methods=["POST"])
def upload_weights():

    global global_model
    global model_version

    data = request.get_json()

    if not data:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400

    weights = data.get("weights")
    received_hash = data.get("hash")

    if not weights or not received_hash:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    if not verify_weights(weights, received_hash):
        return jsonify({"status": "rejected", "message": "Hash mismatch"}), 400

    print("Secure weights received and verified.")

    with pool_lock:

        model_pool.append(weights)

        print(f"Models collected: {len(model_pool)}/{MIN_CLIENTS}")

        if len(model_pool) >= MIN_CLIENTS:

            print("Aggregating global model...")

            global_model = aggregate_models(model_pool)

            model_pool.clear()

            model_version += 1

            save_global_model(global_model)

            print("Global model created.")
            print("Model version:", model_version)

            return jsonify({
                "status": "aggregated",
                "model_version": model_version
            })

    return jsonify({
        "status": "accepted",
        "message": "Waiting for more clients"
    })


@app.route("/global_model", methods=["GET"])
def get_global_model():

    global global_model
    global model_version

    if global_model is None:
        return jsonify({"status": "no_model"}), 404

    return jsonify({
        "model_version": model_version,
        "weights": global_model
    })


if __name__ == "__main__":

    load_global_model()

    context = ("cert.pem", "key.pem")

    app.run(
        host="0.0.0.0",
        port=8000,
        ssl_context=context
    )
