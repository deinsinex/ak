from flask import Flask, request, jsonify
import json
import os
import threading
import time

app = Flask(__name__)

INTEL_FILE = "federation/threat_feed.json"

lock = threading.Lock()

if not os.path.exists(INTEL_FILE):
    with open(INTEL_FILE, "w") as f:
        json.dump({}, f)


def load_intel():

    try:
        with open(INTEL_FILE) as f:
            return json.load(f)
    except:
        return {}


def save_intel(data):

    with open(INTEL_FILE, "w") as f:
        json.dump(data, f, indent=4)


@app.route("/submit_intel", methods=["POST"])
def submit_intel():

    data = request.get_json()

    ip = data.get("ip")
    reason = data.get("reason")

    if not ip:
        return jsonify({"status": "invalid"}), 400

    with lock:

        intel = load_intel()

        intel[ip] = {
            "reason": reason,
            "timestamp": time.time()
        }

        save_intel(intel)

    print("New threat intel received:", ip)

    return jsonify({"status": "stored"})


@app.route("/get_intel", methods=["GET"])
def get_intel():

    intel = load_intel()

    return jsonify(intel)


if __name__ == "__main__":

    print("Threat Intelligence Server running on port 8200")

    app.run(
        host="0.0.0.0",
        port=8200
    )
