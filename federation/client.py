import requests
import urllib3

from federation.crypto_utils import (
    add_dp_noise,
    generate_mask,
    apply_mask,
    hash_weights
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SERVER_URL = "https://localhost:8000/upload_weights"


def send_weights(weights: dict):

    try:

        # differential privacy
        noisy_weights = add_dp_noise(weights)

        # secure mask
        mask = generate_mask(noisy_weights)

        masked_weights = apply_mask(noisy_weights, mask)

        weight_hash = hash_weights(masked_weights)

        payload = {

            "weights": masked_weights,

            "hash": weight_hash
        }

        response = requests.post(
            SERVER_URL,
            json=payload,
            verify=False,
            timeout=10
        )

        print("\nSecure federated update sent")

        print("Server response:", response.status_code)

        try:
            print(response.json())
        except Exception:
            print(response.text)

    except requests.exceptions.RequestException as e:

        print("Federation transmission failed:", e)
