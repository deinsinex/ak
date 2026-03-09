from collections import defaultdict
import time


class ScanDetector:

    def __init__(self):

        self.connection_tracker = defaultdict(list)

        self.TIME_WINDOW = 10
        self.SCAN_THRESHOLD = 15

        self.last_cleanup = time.time()
        self.CLEANUP_INTERVAL = 60


    def analyze(self, event):

        ip = event.source_ip
        now = time.time()

        self.connection_tracker[ip].append(now)

        # Sliding time window
        self.connection_tracker[ip] = [
            t for t in self.connection_tracker[ip]
            if now - t < self.TIME_WINDOW
        ]

        count = len(self.connection_tracker[ip])

        if count >= self.SCAN_THRESHOLD:

            print(f"\n⚠️ PORT SCAN DETECTED from {ip} ({count} connections)")

            self.connection_tracker[ip] = []

            return True

        # Periodic cleanup of stale IP entries
        if now - self.last_cleanup > self.CLEANUP_INTERVAL:

            for tracked_ip in list(self.connection_tracker.keys()):
                if not self.connection_tracker[tracked_ip]:
                    del self.connection_tracker[tracked_ip]

            self.last_cleanup = now

        return False
