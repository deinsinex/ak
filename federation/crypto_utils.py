import hashlib
import json
import numpy as np
import secrets


def add_dp_noise(weights: dict, epsilon: float = 0.5) -> dict:

    noisy_weights = {}

    for key, value in weights.items():

        try:
            value = float(value)
        except Exception:
            continue

        noise = np.random.normal(
            loc=0.0,
            scale=1.0 / epsilon
        )

        noisy_weights[key] = float(value + noise)

    return noisy_weights


def generate_mask(weights):

    mask = {}

    for k in weights:
        mask[k] = secrets.randbelow(1000) / 1000.0

    return mask


def apply_mask(weights, mask):

    masked = {}

    for k in weights:

        masked[k] = float(weights[k] + mask.get(k, 0))

    return masked


def remove_mask(weights, mask):

    unmasked = {}

    for k in weights:

        unmasked[k] = float(weights[k] - mask.get(k, 0))

    return unmasked


def hash_weights(weights: dict) -> str:

    normalized = {
        k: round(float(v), 8)
        for k, v in weights.items()
    }

    weights_string = json.dumps(
        normalized,
        sort_keys=True
    ).encode()

    return hashlib.sha256(weights_string).hexdigest()


def verify_weights(weights: dict, received_hash: str) -> bool:

    computed_hash = hash_weights(weights)

    return computed_hash == received_hash
