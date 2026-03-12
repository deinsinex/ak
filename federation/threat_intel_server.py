from flask import Flask, request, jsonify
import os
import json
import time
import threading

app = Flask(__name__)

THREAT_FEED_FILE = "federation/threat_feed.json"
feed_lock = threading.Lock()


# =========================================================
# HELPERS
# =========================================================

def ensure_feed_file():
    os.makedirs("federation", exist_ok=True)

    if not os.path.exists(THREAT_FEED_FILE):
        with open(THREAT_FEED_FILE, "w") as f:
            json.dump({}, f, indent=4)


def load_feed():
    ensure_feed_file()

    try:
        if os.path.getsize(THREAT_FEED_FILE) == 0:
            return {}

        with open(THREAT_FEED_FILE, "r") as f:
            data = json.load(f)

        if isinstance(data, dict):
            return data

        return {}

    except Exception as e:
        print(f"[THREAT INTEL] Failed to load feed: {e}")
        return {}


def save_feed(feed):
    ensure_feed_file()

    with open(THREAT_FEED_FILE, "w") as f:
        json.dump(feed, f, indent=4)


def score_for_event(event_name):
    """
    Assign a collaborative reputation score based on event severity.
    """
    mapping = {
        "PORT_SCAN": 60,
        "PAYLOAD_ATTACK": 85,
        "ML_ATTACK": 75,
        "COLLAB_THREAT_FEED": 70,
        "NULL_SCAN": 65,
        "XMAS_SCAN": 65,
        "FIN_SCAN": 60,
        "SYN_FLOOD": 80,
        "BASELINE_ANOMALY": 40,
        "ATTACK_SEQUENCE": 90
    }

    return mapping.get(event_name, 50)


# =========================================================
# ROUTES
# =========================================================

@app.route("/report_threat", methods=["POST"])
def report_threat():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"status": "error", "message": "Missing JSON body"}), 400

    ip = str(data.get("ip", "")).strip()
    event_name = str(data.get("event", "SHARED_THREAT")).strip()

    if not ip:
        return jsonify({"status": "error", "message": "Missing IP"}), 400

    with feed_lock:
        feed = load_feed()

        existing = feed.get(ip, {})

        old_score = int(existing.get("score", 0))
        new_score = score_for_event(event_name)

        # Keep the highest known severity
        final_score = max(old_score, new_score)

        count = int(existing.get("count", 0)) + 1

        feed[ip] = {
            "score": final_score,
            "reason": event_name,
            "source": "shared_intel",
            "timestamp": time.time(),
            "count": count
        }

        save_feed(feed)

    print(f"[THREAT INTEL] Recorded {event_name} for {ip} (score={final_score}, count={count})")

    return jsonify({
        "status": "ok",
        "ip": ip,
        "score": final_score,
        "count": count
    })


@app.route("/threat_feed", methods=["GET"])
def threat_feed():
    with feed_lock:
        feed = load_feed()

    return jsonify({
        "status": "ok",
        "count": len(feed),
        "feed": feed
    })


@app.route("/health", methods=["GET"])
def health():
    with feed_lock:
        feed = load_feed()

    return jsonify({
        "status": "ok",
        "service": "Aegis Threat Intel Server",
        "entries": len(feed)
    })


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    ensure_feed_file()

    context = ("cert.pem", "key.pem")

    print("🧠 Aegis Threat Intel Server Running")
    print("🔐 HTTPS: https://127.0.0.1:8100")

    app.run(
        host="0.0.0.0",
        port=8100,
        ssl_context=context,
        debug=False,
        use_reloader=False
    )
