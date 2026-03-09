import requests
import urllib3

from federation.crypto_utils import hash_weights, add_dp_noise


# Disable SSL warnings for local testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SERVER_URL = "https://localhost:8000/upload_weights"


def send_weights(weights: dict):
    """
    Send differentially private weights to the federation server.

    Raw model weights NEVER leave the edge device.
    """

    if not weights:
        print("No weights to send.")
        return

    try:

        # Apply Differential Privacy
        noisy_weights = add_dp_noise(weights)

        # Hash noisy weights for integrity verification
        weight_hash = hash_weights(noisy_weights)

        payload = {
            "weights": noisy_weights,
            "hash": weight_hash
        }

        response = requests.post(
            SERVER_URL,
            json=payload,
            verify=False,   # only for local testing
            timeout=10
        )

        print("\nFederation server response:")
        print(response.status_code)

        if response.status_code != 200:
            print("Server returned error.")

        try:
            print(response.json())
        except Exception:
            print(response.text)

    except requests.exceptions.RequestException as e:

        print("Federation transmission failed:", e)
