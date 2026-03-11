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

    with open(MODEL_FILE, "w") as f:
        json.dump(model, f)


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
        return jsonify({"status": "error"}), 400

    weights = data.get("weights")
    received_hash = data.get("hash")

    if not verify_weights(weights, received_hash):

        return jsonify({"status": "hash_mismatch"}), 400

    print("Secure masked weights received")

    with pool_lock:

        model_pool.append(weights)

        print(f"Clients received: {len(model_pool)}/{MIN_CLIENTS}")

        if len(model_pool) >= MIN_CLIENTS:

            print("Performing secure aggregation")

            global_model = aggregate_models(model_pool)

            model_pool.clear()

            model_version += 1

            save_global_model(global_model)

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

    if global_model is None:
        return jsonify({"status": "no_model"}), 404

    return jsonify({

        "model_version": model_version,

        "weights": global_model
    })


if __name__ == "__main__":

    context = ("cert.pem", "key.pem")

    print("Secure Federated Server Running")

    app.run(

        host="0.0.0.0",

        port=8000,

        ssl_context=context
    )
