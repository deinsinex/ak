import json
import os
import time


DB_FILE = "intel/threat_reputation.json"
MAX_HISTORY = 50
DECAY_TIME = 86400   # 24 hours


class ThreatMemory:

    def __init__(self):

        os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)

        if not os.path.exists(DB_FILE):

            with open(DB_FILE, "w") as f:
                json.dump({}, f)

        self.db = self.load_db()


    def load_db(self):

        try:

            with open(DB_FILE) as f:
                return json.load(f)

        except Exception:

            print("⚠️ Threat DB corrupted, rebuilding.")
            return {}


    def save_db(self):

        temp_file = DB_FILE + ".tmp"

        with open(temp_file, "w") as f:
            json.dump(self.db, f, indent=4)

        os.replace(temp_file, DB_FILE)


    def decay_score(self, entry):

        now = time.time()

        last = entry.get("last_seen")

        if last is None:
            return

        if now - last > DECAY_TIME:

            entry["score"] = max(0, int(entry.get("score", 0)) - 10)

            entry["last_seen"] = now


    def record_attack(self, ip, event_type):

        if ip not in self.db:

            self.db[ip] = {
                "score": 0,
                "attacks": [],
                "last_seen": None
            }

        entry = self.db[ip]

        self.decay_score(entry)

        entry["score"] += 10

        entry["attacks"].append({
            "type": event_type,
            "time": time.time()
        })

        if len(entry["attacks"]) > MAX_HISTORY:

            entry["attacks"] = entry["attacks"][-MAX_HISTORY:]

        entry["last_seen"] = time.time()

        self.save_db()


    def get_reputation(self, ip):

        entry = self.db.get(ip)

        if not entry:
            return 0

        self.decay_score(entry)

        return entry.get("score", 0)


    def is_known_attacker(self, ip):

        score = self.get_reputation(ip)

        return score >= 50
