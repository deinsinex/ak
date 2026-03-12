import os
import time
from core.json_store import JsonStore


class ThreatIntel:
    def __init__(self, db_path="data/threat_memory.json"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.db = self._load_db()

    def _load_db(self):
        data = JsonStore.load(self.db_path, {})
        if not isinstance(data, dict):
            print("⚠️ Threat DB corrupted, rebuilding.")
            data = {}
            JsonStore.save(self.db_path, data)
        return data

    def _save_db(self):
        JsonStore.save(self.db_path, self.db)

    def get_score(self, ip):
        entry = self.db.get(ip, {})
        return int(entry.get("score", 0))

    def get_reason(self, ip):
        entry = self.db.get(ip, {})
        return entry.get("reason", "UNKNOWN")

    def record(self, ip, reason, delta):
        if not ip:
            return

        entry = self.db.get(ip, {
            "score": 0,
            "reason": reason,
            "last_seen": time.strftime("%Y-%m-%d %H:%M:%S"),
            "history": []
        })

        entry["score"] = int(entry.get("score", 0)) + int(delta)
        entry["reason"] = reason
        entry["last_seen"] = time.strftime("%Y-%m-%d %H:%M:%S")

        history = entry.get("history", [])
        history.append({
            "timestamp": entry["last_seen"],
            "reason": reason,
            "delta": int(delta),
            "score_after": entry["score"]
        })

        # Keep only latest 50 events per IP
        entry["history"] = history[-50:]

        self.db[ip] = entry
        self._save_db()

        print(f"[THREAT INTEL] Recorded {reason} for {ip} (+{delta})")

    def clear(self):
        self.db = {}
        self._save_db()
        print("[THREAT INTEL] Cleared DB")
