import os
import json
import time


STATE_FILE = "core/trust_state.json"


class TrustEngine:

    def __init__(self):
        self.trust_scores = {}
        self.last_seen = {}
        self.MAX_TRUST = 100
        self.MIN_TRUST = 0
        self.DEFAULT_TRUST = 50

        self.RECOVERY_INTERVAL = 120      # seconds
        self.RECOVERY_POINTS = 2          # trust points recovered per interval
        self.STALE_RESET_AFTER = 3600     # 1 hour

        self._load_state()

    # ==========================================
    # PERSISTENCE
    # ==========================================

    def _load_state(self):
        try:
            if not os.path.exists(STATE_FILE):
                return

            if os.path.getsize(STATE_FILE) == 0:
                return

            with open(STATE_FILE, "r") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                return

            self.trust_scores = data.get("trust_scores", {})
            self.last_seen = data.get("last_seen", {})

            # normalize values
            self.trust_scores = {
                str(ip): int(score)
                for ip, score in self.trust_scores.items()
            }

            self.last_seen = {
                str(ip): float(ts)
                for ip, ts in self.last_seen.items()
            }

            print(f"[TRUST] Loaded {len(self.trust_scores)} trust entries")

        except Exception as e:
            print(f"[TRUST] Failed to load state: {e}")
            self.trust_scores = {}
            self.last_seen = {}

    def _save_state(self):
        try:
            os.makedirs("core", exist_ok=True)

            data = {
                "trust_scores": self.trust_scores,
                "last_seen": self.last_seen
            }

            with open(STATE_FILE, "w") as f:
                json.dump(data, f, indent=4)

        except Exception as e:
            print(f"[TRUST] Failed to save state: {e}")

    # ==========================================
    # INTERNAL HELPERS
    # ==========================================

    def _clamp(self, score):
        if score > self.MAX_TRUST:
            return self.MAX_TRUST
        if score < self.MIN_TRUST:
            return self.MIN_TRUST
        return score

    def _touch(self, ip):
        self.last_seen[ip] = time.time()

    def _ensure_ip(self, ip):
        if ip not in self.trust_scores:
            self.trust_scores[ip] = self.DEFAULT_TRUST
        if ip not in self.last_seen:
            self.last_seen[ip] = time.time()

    # ==========================================
    # TRUST QUERIES
    # ==========================================

    def get_trust(self, ip):
        self._ensure_ip(ip)
        self._apply_decay_for_ip(ip)
        return self.trust_scores.get(ip, self.DEFAULT_TRUST)

    def get_state(self, ip):
        score = self.get_trust(ip)

        if score >= 80:
            return "TRUSTED"
        elif score >= 50:
            return "NORMAL"
        elif score >= 20:
            return "SUSPICIOUS"
        else:
            return "UNTRUSTED"

    def is_untrusted(self, ip):
        return self.get_trust(ip) < 20

    def is_suspicious(self, ip):
        return self.get_trust(ip) < 50

    # ==========================================
    # TRUST EVENTS
    # ==========================================

    def record_benign(self, ip, points=1):
        self._ensure_ip(ip)
        self._apply_decay_for_ip(ip)

        score = self.trust_scores[ip]
        score += points

        self.trust_scores[ip] = self._clamp(score)
        self._touch(ip)
        self._save_state()

    def record_suspicious(self, ip, points=10):
        self._ensure_ip(ip)
        self._apply_decay_for_ip(ip)

        score = self.trust_scores[ip]
        score -= points

        self.trust_scores[ip] = self._clamp(score)
        self._touch(ip)
        self._save_state()

    def record_attack(self, ip, points=30):
        self._ensure_ip(ip)
        self._apply_decay_for_ip(ip)

        score = self.trust_scores[ip]
        score -= points

        self.trust_scores[ip] = self._clamp(score)
        self._touch(ip)
        self._save_state()

    def reward_trust(self, ip, points=5):
        self._ensure_ip(ip)
        self._apply_decay_for_ip(ip)

        self.trust_scores[ip] = self._clamp(self.trust_scores[ip] + points)
        self._touch(ip)
        self._save_state()

    def penalize(self, ip, points=15):
        self._ensure_ip(ip)
        self._apply_decay_for_ip(ip)

        self.trust_scores[ip] = self._clamp(self.trust_scores[ip] - points)
        self._touch(ip)
        self._save_state()

    # ==========================================
    # DECAY / AGING LOGIC
    # ==========================================

    def _apply_decay_for_ip(self, ip):
        """
        Slowly recover trust over time for inactive hosts.
        If an IP is stale for a very long time, gradually move toward default trust.
        """
        if ip not in self.last_seen:
            return

        now = time.time()
        last = self.last_seen[ip]
        elapsed = now - last

        # gradual recovery if enough time passed
        if elapsed >= self.RECOVERY_INTERVAL:
            intervals = int(elapsed // self.RECOVERY_INTERVAL)
            recovery = intervals * self.RECOVERY_POINTS

            current = self.trust_scores.get(ip, self.DEFAULT_TRUST)

            # recover upward toward DEFAULT_TRUST if below it
            if current < self.DEFAULT_TRUST:
                current = min(self.DEFAULT_TRUST, current + recovery)

            # or slightly recover upward if already above default but cap at MAX_TRUST
            elif current < self.MAX_TRUST:
                current = min(self.MAX_TRUST, current + max(1, intervals // 2))

            self.trust_scores[ip] = self._clamp(current)

            # move forward the timestamp anchor to avoid double-counting same elapsed time
            self.last_seen[ip] = now
            self._save_state()

        # if very stale and entry somehow missing score, normalize
        if elapsed >= self.STALE_RESET_AFTER and ip not in self.trust_scores:
            self.trust_scores[ip] = self.DEFAULT_TRUST
            self._save_state()

    def apply_decay_all(self):
        for ip in list(self.trust_scores.keys()):
            self._apply_decay_for_ip(ip)

    # ==========================================
    # MAINTENANCE
    # ==========================================

    def reset(self):
        self.trust_scores = {}
        self.last_seen = {}

        try:
            if os.path.exists(STATE_FILE):
                os.remove(STATE_FILE)
        except Exception as e:
            print(f"[TRUST] Failed to remove state file: {e}")

        print("[TRUST] Trust memory reset")

    def remove_ip(self, ip):
        if ip in self.trust_scores:
            del self.trust_scores[ip]

        if ip in self.last_seen:
            del self.last_seen[ip]

        self._save_state()

    def get_all(self):
        self.apply_decay_all()

        result = {}

        for ip, score in self.trust_scores.items():
            result[ip] = {
                "score": score,
                "state": self.get_state(ip),
                "last_seen": self.last_seen.get(ip)
            }

        return result

    def summary(self):
        self.apply_decay_all()

        total = len(self.trust_scores)
        trusted = 0
        normal = 0
        suspicious = 0
        untrusted = 0

        for ip in self.trust_scores:
            state = self.get_state(ip)

            if state == "TRUSTED":
                trusted += 1
            elif state == "NORMAL":
                normal += 1
            elif state == "SUSPICIOUS":
                suspicious += 1
            else:
                untrusted += 1

        return {
            "total_hosts": total,
            "trusted": trusted,
            "normal": normal,
            "suspicious": suspicious,
            "untrusted": untrusted
        }
