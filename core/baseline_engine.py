import time
from collections import defaultdict


class BaselineEngine:

    def __init__(self):

        # Track per-IP statistics
        self.ip_stats = defaultdict(lambda: {
            "packet_count": 0,
            "first_seen": time.time(),
            "last_seen": time.time()
        })

        # Baseline thresholds (adaptive)
        self.NORMAL_RATE = 20   # packets/sec allowed normally
        self.SUSPICIOUS_RATE = 50

    def update(self, ip):

        entry = self.ip_stats[ip]

        now = time.time()

        entry["packet_count"] += 1
        entry["last_seen"] = now

        duration = now - entry["first_seen"]

        if duration <= 0:
            return "NORMAL"

        rate = entry["packet_count"] / duration

        if rate > self.SUSPICIOUS_RATE:
            return "ANOMALOUS"

        if rate > self.NORMAL_RATE:
            return "ELEVATED"

        return "NORMAL"

    def reset(self, ip):

        if ip in self.ip_stats:
            del self.ip_stats[ip]
