import requests
import json
import os
import urllib3


# Disable SSL warnings for local lab use
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SERVER_URL = "https://localhost:8000/global_model"

LOCAL_MODEL_FILE = "federation/local_model.json"
LOCAL_VERSION_FILE = "federation/local_model_version.txt"


def get_local_version():

    if not os.path.exists(LOCAL_VERSION_FILE):
        return 0

    try:
        with open(LOCAL_VERSION_FILE, "r") as f:
            return int(f.read().strip())
    except Exception:
        return 0


def save_local_model(model_version, weights):

    os.makedirs("federation", exist_ok=True)

    temp_model = LOCAL_MODEL_FILE + ".tmp"

    with open(temp_model, "w") as f:
        json.dump(weights, f)

    os.replace(temp_model, LOCAL_MODEL_FILE)

    with open(LOCAL_VERSION_FILE, "w") as f:
        f.write(str(model_version))


def fetch_global_model():

    local_version = get_local_version()

    try:

        response = requests.get(
            SERVER_URL,
            verify=False,
            timeout=10
        )

        if response.status_code != 200:
            print("No global model available yet.")
            return None

        try:
            data = response.json()
        except Exception:
            print("Invalid JSON from server.")
            return None

        model_version = data.get("model_version")
        weights = data.get("weights")

        if not isinstance(model_version, int):
            print("Invalid model version.")
            return None

        if not isinstance(weights, dict):
            print("Invalid weights received.")
            return None

        if model_version <= local_version:
            print("Local model already up to date.")
            return None

        print(f"New global model received (version {model_version})")

        save_local_model(model_version, weights)

        print("Global model stored locally.")

        return weights

    except requests.exceptions.RequestException as e:

        print("Failed to fetch model:", e)

        return None
