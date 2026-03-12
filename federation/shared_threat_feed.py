import os
import time
from core.json_store import JsonStore

THREAT_FEED_PATH = os.path.join("federation", "threat_feed.json")


def load_shared_threats():
    data = JsonStore.load(THREAT_FEED_PATH, {})
    if not isinstance(data, dict):
        return {}
    return data


def save_shared_threats(data: dict):
    if not isinstance(data, dict):
        data = {}
    JsonStore.save(THREAT_FEED_PATH, data)


def add_shared_threat(ip: str, reason: str, score: int = 60):
    if not ip:
        return

    data = load_shared_threats()
    existing = data.get(ip, {})

    data[ip] = {
        "reason": reason,
        "score": max(score, int(existing.get("score", 0))),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    save_shared_threats(data)
