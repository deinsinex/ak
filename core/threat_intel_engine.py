import json
import os
import time
import tempfile
from collections import defaultdict


class ThreatIntelEngine:
    """
    Local threat intelligence memory for Aegis.

    Responsibilities:
    - Keep per-IP event history
    - Maintain reputation score
    - Store last seen / first seen timestamps
    - Persist to disk so detections survive restarts
    """

    def __init__(self, db_file="intel/threat_reputation.json"):
        self.db_file = db_file

        self.reputation = {}
        self.event_history = defaultdict(list)

        self._load()

    # =========================================================
    # INTERNAL HELPERS
    # =========================================================

    def _ensure_parent_dir(self):
        parent = os.path.dirname(self.db_file)
        if parent:
            os.makedirs(parent, exist_ok=True)

    def _atomic_save_json(self, data):
        """
        Atomic write to avoid partial/corrupt JSON files.
        """
        self._ensure_parent_dir()

        parent = os.path.dirname(self.db_file) or "."
        fd, tmp_path = tempfile.mkstemp(prefix=".tmp_threat_", suffix=".json", dir=parent)

        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())

            os.replace(tmp_path, self.db_file)

        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    def _load(self):
        if not os.path.exists(self.db_file):
            return

        try:
            with open(self.db_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                raise ValueError("Threat DB root is not a JSON object")

            self.reputation = data.get("reputation", {})
            if not isinstance(self.reputation, dict):
                self.reputation = {}

            raw_history = data.get("event_history", {})
            if not isinstance(raw_history, dict):
                raw_history = {}

            self.event_history = defaultdict(list, raw_history)

            print(f"[THREAT INTEL] Loaded {len(self.reputation)} local reputation entries")

        except Exception as e:
            print(f"[THREAT INTEL] Failed to load DB: {e}")
            self.reputation = {}
            self.event_history = defaultdict(list)

    def _save(self):
        try:
            data = {
                "reputation": self.reputation,
                "event_history": dict(self.event_history)
            }
            self._atomic_save_json(data)

        except Exception as e:
            print(f"[THREAT INTEL] Failed to save DB: {e}")

    def _event_weight(self, event_name):
        """
        Keep local persistent reputation aligned with calmer main.py runtime scoring.
        IMPORTANT: These weights should roughly match the weights passed from main.py
        so logs + persistent reputation remain consistent.
        """
        weights = {
            "COLLAB_THREAT_FEED": 35,   # was 70 (too aggressive)
            "ATTACK_SEQUENCE": 80,
            "ML_ATTACK": 35,            # was 85 (too aggressive)
            "ML_ATTACK_DETECTED": 35,
            "PAYLOAD_ATTACK": 60,
            "PORT_SCAN": 40,
            "SYN_SCAN": 50,
            "FIN_SCAN": 50,
            "XMAS_SCAN": 50,
            "NULL_SCAN": 50,
            "BASELINE_ANOMALY": 15,     # was 30 (too noisy)
            "KNOWN_ATTACKER": 90,
        }

        return weights.get(event_name, 20)

    # =========================================================
    # PUBLIC API USED BY main.py
    # =========================================================

    def record_event(self, ip, event_name):
        """
        Required by main.py.
        Records a threat event locally and updates reputation.
        """
        now = int(time.time())
        weight = self._event_weight(event_name)

        event = {
            "event": event_name,
            "weight": weight,
            "timestamp": now
        }

        self.event_history[ip].append(event)

        # keep history bounded
        if len(self.event_history[ip]) > 100:
            self.event_history[ip] = self.event_history[ip][-100:]

        entry = self.reputation.get(ip, {
            "score": 0,
            "first_seen": now,
            "last_seen": now,
            "events": 0,
            "last_event": None
        })

        entry["score"] = min(1000, entry.get("score", 0) + weight)
        entry["last_seen"] = now
        entry["events"] = entry.get("events", 0) + 1
        entry["last_event"] = event_name

        self.reputation[ip] = entry

        self._save()

        print(f"[THREAT INTEL] Recorded {event_name} for {ip} (+{weight})")

    # =========================================================
    # OPTIONAL HELPERS FOR FUTURE MODULES
    # =========================================================

    def get_score(self, ip):
        return self.reputation.get(ip, {}).get("score", 0)

    def is_high_risk(self, ip, threshold=120):
        return self.get_score(ip) >= threshold

    def get_history(self, ip):
        return self.event_history.get(ip, [])

    def summary(self):
        return {
            "tracked_ips": len(self.reputation),
            "high_risk_ips": len([ip for ip, data in self.reputation.items() if data.get("score", 0) >= 120])
        }

    def clear(self):
        self.reputation = {}
        self.event_history = defaultdict(list)
        self._save()
        print("[THREAT INTEL] Local threat DB cleared")
