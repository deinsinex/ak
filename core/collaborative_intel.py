import os
import json
import time


THREAT_FEED_FILE = "federation/threat_feed.json"


class CollaborativeIntel:

    def __init__(self, feed_file=THREAT_FEED_FILE):
        self.feed_file = feed_file
        self.shared_threats = {}
        self.last_loaded = 0
        self.last_mtime = 0
        self.refresh()

    def _safe_load_json(self, path):
        """
        Safely load JSON file.
        Returns {} if file missing / empty / invalid.
        """
        try:
            if not os.path.exists(path):
                return {}

            if os.path.getsize(path) == 0:
                return {}

            with open(path, "r") as f:
                data = json.load(f)

            if isinstance(data, dict):
                return data

            return {}

        except Exception as e:
            print(f"[COLLAB INTEL] Failed to load {path}: {e}")
            return {}

    def _normalize_feed(self, raw_data):
        """
        Normalize multiple possible threat feed formats into:
        {
            "ip": {
                "score": int,
                "reason": str,
                "source": str,
                "timestamp": float
            }
        }
        """

        normalized = {}

        # Case 1:
        # {
        #   "1.2.3.4": {"score": 80, "reason": "PORT_SCAN"}
        # }
        if all(isinstance(v, dict) for v in raw_data.values()) if raw_data else True:
            for ip, info in raw_data.items():
                if not isinstance(ip, str):
                    continue

                if not isinstance(info, dict):
                    info = {}

                normalized[ip] = {
                    "score": int(info.get("score", 50)),
                    "reason": str(info.get("reason", "SHARED_THREAT")),
                    "source": str(info.get("source", "federation")),
                    "timestamp": float(info.get("timestamp", time.time()))
                }

            return normalized

        # Fallback
        return {}

    def refresh(self):
        """
        Reload feed if changed.
        """
        try:
            if not os.path.exists(self.feed_file):
                self.shared_threats = {}
                self.last_loaded = time.time()
                self.last_mtime = 0
                return

            current_mtime = os.path.getmtime(self.feed_file)

            if current_mtime == self.last_mtime and self.shared_threats:
                return

            raw = self._safe_load_json(self.feed_file)
            self.shared_threats = self._normalize_feed(raw)

            self.last_loaded = time.time()
            self.last_mtime = current_mtime

            print(f"[COLLAB INTEL] Loaded {len(self.shared_threats)} shared threat(s)")

        except Exception as e:
            print(f"[COLLAB INTEL] Refresh failed: {e}")
            self.shared_threats = {}

    def is_shared_threat(self, ip):
        self.refresh()
        return ip in self.shared_threats

    def get_shared_score(self, ip):
        self.refresh()

        if ip not in self.shared_threats:
            return 0

        return int(self.shared_threats[ip].get("score", 50))

    def get_shared_reason(self, ip):
        self.refresh()

        if ip not in self.shared_threats:
            return None

        return self.shared_threats[ip].get("reason", "SHARED_THREAT")

    def get_shared_source(self, ip):
        self.refresh()

        if ip not in self.shared_threats:
            return None

        return self.shared_threats[ip].get("source", "federation")

    def get_shared_timestamp(self, ip):
        self.refresh()

        if ip not in self.shared_threats:
            return None

        return self.shared_threats[ip].get("timestamp")

    def get_threat_info(self, ip):
        self.refresh()

        if ip not in self.shared_threats:
            return None

        return self.shared_threats[ip]

    def get_all_shared_threats(self):
        self.refresh()
        return self.shared_threats

    def count(self):
        self.refresh()
        return len(self.shared_threats)

    def clear_cache(self):
        """
        Clears only in-memory cache.
        Does not delete file.
        """
        self.shared_threats = {}
        self.last_loaded = 0
        self.last_mtime = 0
        print("[COLLAB INTEL] Cache cleared")
