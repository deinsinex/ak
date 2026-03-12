import os
import json
import time
import ipaddress


THREAT_FEED_FILE = "federation/threat_feed.json"


class CollaborativeIntel:

    def __init__(self, feed_file=THREAT_FEED_FILE):
        self.feed_file = feed_file
        self.shared_threats = {}
        self.last_loaded = 0
        self.last_mtime = 0
        self.refresh()

    def _is_valid_remote_ip(self, ip):
        """
        Keep only public routable IPs in shared intel.
        Avoid poisoning with local/private/loopback/etc.
        """
        try:
            addr = ipaddress.ip_address(ip)
            return not (
                addr.is_private or
                addr.is_loopback or
                addr.is_link_local or
                addr.is_multicast or
                addr.is_reserved or
                addr.is_unspecified
            )
        except Exception:
            return False

    def _safe_load_json(self):
        """
        Safely load the threat feed JSON file.
        Expected normalized format:
        {
            "ip": {
                "score": int,
                "reason": str,
                "source": str,
                "timestamp": float,
                "count": int
            }
        }
        """
        try:
            if not os.path.exists(self.feed_file):
                return {}

            if os.path.getsize(self.feed_file) == 0:
                return {}

            with open(self.feed_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                return {}

            normalized = {}
            now = time.time()

            for ip, info in data.items():
                if not isinstance(ip, str):
                    continue

                if not self._is_valid_remote_ip(ip):
                    continue

                if not isinstance(info, dict):
                    continue

                score = int(info.get("score", 50))
                score = max(0, min(score, 100))  # clamp 0..100

                timestamp = float(info.get("timestamp", now))

                # Expire very old intel automatically (24 hours)
                if (now - timestamp) > 86400:
                    continue

                normalized[ip] = {
                    "score": score,
                    "reason": str(info.get("reason", "SHARED_THREAT")),
                    "source": str(info.get("source", "shared_intel")),
                    "timestamp": timestamp,
                    "count": int(info.get("count", 1))
                }

            return normalized

        except Exception as e:
            print(f"[COLLAB INTEL] Failed to load {self.feed_file}: {e}")
            return {}

    def refresh(self):
        """
        Reload the threat feed if the file changed.
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

            self.shared_threats = self._safe_load_json()
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

        return self.shared_threats[ip].get("source", "shared_intel")

    def get_shared_timestamp(self, ip):
        self.refresh()

        if ip not in self.shared_threats:
            return None

        return self.shared_threats[ip].get("timestamp")

    def get_shared_count(self, ip):
        self.refresh()

        if ip not in self.shared_threats:
            return 0

        return int(self.shared_threats[ip].get("count", 1))

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
        Does not delete the underlying file.
        """
        self.shared_threats = {}
        self.last_loaded = 0
        self.last_mtime = 0
        print("[COLLAB INTEL] Cache cleared")
