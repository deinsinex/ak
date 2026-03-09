import hashlib
import json
import numpy as np


def add_dp_noise(weights: dict, epsilon: float = 0.5) -> dict:
    """
    Apply Differential Privacy noise to model weights.

    epsilon ↓  → stronger privacy
    epsilon ↑  → weaker privacy
    """

    noisy_weights = {}

    for key, value in weights.items():

        try:
            value = float(value)
        except Exception:
            continue

        if not np.isfinite(value):
            continue

        noise = np.random.normal(
            loc=0.0,
            scale=1.0 / epsilon
        )

        noisy_weights[key] = float(value + noise)

    return noisy_weights


def hash_weights(weights: dict) -> str:
    """
    Generate SHA256 hash for weight integrity verification.
    """

    normalized = {
        k: round(float(v), 8)
        for k, v in weights.items()
        if np.isfinite(float(v))
    }

    weights_string = json.dumps(
        normalized,
        sort_keys=True
    ).encode()

    return hashlib.sha256(weights_string).hexdigest()


def verify_weights(weights: dict, received_hash: str) -> bool:
    """
    Verify integrity of received model weights.
    """

    computed_hash = hash_weights(weights)

    return computed_hash == received_hash
