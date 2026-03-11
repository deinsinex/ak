from flask import Flask, request, jsonify
import json
import os
import threading
import time


app = Flask(__name__)

# =============================
# CONFIG
# =============================

DB_FILE = "federation/threat_feed.json"
MAX_REPORTS = 500
THREAT_TTL = 86400  # 24 hours

feed_lock = threading.Lock()

# In-memory structure
threat_feed = {
    "reported_threats": [],
    "blocked_ips": []
}


# =============================
# HELPERS
# =============================

def ensure_db():
    os.makedirs("federation", exist_ok=True)

    if not os.path.exists(DB_FILE):
        with open(DB_FILE, "w") as f:
            json.dump(threat_feed, f, indent=4)


def load_feed():
    global threat_feed

    ensure_db()

    try:
        with open(DB_FILE, "r") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            raise ValueError("Invalid feed format")

        reported = data.get("reported_threats", [])
        blocked = data.get("blocked_ips", [])

        if not isinstance(reported, list):
            reported = []

        if not isinstance(blocked, list):
            blocked = []

        threat_feed = {
            "reported_threats": reported,
            "blocked_ips": blocked
        }

        print("Loaded collaborative threat feed.")

    except Exception as e:
        print(f"Threat feed corrupted or unreadable. Rebuilding. ({e})")
        threat_feed = {
            "reported_threats": [],
            "blocked_ips": []
        }
        save_feed()


def save_feed():
    temp_file = DB_FILE + ".tmp"

    with open(temp_file, "w") as f:
        json.dump(threat_feed, f, indent=4)

    os.replace(temp_file, DB_FILE)


def cleanup_expired_reports():
    """
    Remove old reports beyond TTL.
    """
    now = time.time()

    fresh_reports = []
    blocked_ips = set()

    for entry in threat_feed["reported_threats"]:
        ts = entry.get("timestamp", 0)

        if now - ts <= THREAT_TTL:
            fresh_reports.append(entry)

            ip = entry.get("ip")
            if ip:
                blocked_ips.add(ip)

    threat_feed["reported_threats"] = fresh_reports[-MAX_REPORTS:]
    threat_feed["blocked_ips"] = sorted(list(blocked_ips))


# =============================
# ROUTES
# =============================

@app.route("/report_threat", methods=["POST"])
def report_threat():
    data = request.get_json()

    if not data:
        return jsonify({
            "status": "error",
            "message": "Invalid JSON"
        }), 400

    ip = data.get("ip")
    reason = data.get("reason", "UNKNOWN")

    if not ip or not isinstance(ip, str):
        return jsonify({
            "status": "error",
            "message": "Missing or invalid IP"
        }), 400

    if not isinstance(reason, str):
        reason = "UNKNOWN"

    entry = {
        "ip": ip,
        "reason": reason,
        "timestamp": time.time()
    }

    with feed_lock:
        cleanup_expired_reports()

        threat_feed["reported_threats"].append(entry)

        if ip not in threat_feed["blocked_ips"]:
            threat_feed["blocked_ips"].append(ip)

        # enforce size limits
        threat_feed["reported_threats"] = threat_feed["reported_threats"][-MAX_REPORTS:]
        threat_feed["blocked_ips"] = sorted(list(set(threat_feed["blocked_ips"])))

        save_feed()

    print(f"[THREAT INTEL] Report received: {ip} ({reason})")

    return jsonify({
        "status": "accepted",
        "ip": ip,
        "reason": reason
    })


@app.route("/threat_feed", methods=["GET"])
def get_threat_feed():
    with feed_lock:
        cleanup_expired_reports()
        save_feed()

        return jsonify({
            "blocked_ips": threat_feed["blocked_ips"],
            "reported_threats": threat_feed["reported_threats"]
        })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "Aegis Threat Intel Server"
    })


# =============================
# MAIN
# =============================

if __name__ == "__main__":
    load_feed()

    context = ("cert.pem", "key.pem")

    print("🌐 Aegis Threat Intel Server running on https://0.0.0.0:8100")

    app.run(
        host="0.0.0.0",
        port=8100,
        ssl_context=context,
        debug=False,
        use_reloader=False
    )
