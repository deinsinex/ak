import time


class RiskEngine:

    def __init__(self):

        # ip -> state
        self.state = {}

        # More realistic decay
        self.SCORE_DECAY_INTERVAL = 60
        self.DECAY_AMOUNT = 8

        # Safer thresholds for demo / real browsing
        self.BLOCK_THRESHOLD = 120
        self.SUSPICIOUS_THRESHOLD = 60

        # Bound event list to avoid memory growth
        self.MAX_EVENTS_PER_IP = 100

    def _get_entry(self, ip):

        if ip not in self.state:

            now = time.time()
            self.state[ip] = {
                "score": 0,
                "events": [],
                "last_seen": now,
                "last_decay": now
            }

        return self.state[ip]

    def decay(self, ip):

        entry = self._get_entry(ip)

        now = time.time()
        elapsed = now - entry["last_decay"]

        if elapsed < self.SCORE_DECAY_INTERVAL:
            return

        # Apply multi-step decay if a long time passed
        intervals = int(elapsed // self.SCORE_DECAY_INTERVAL)
        decay_total = intervals * self.DECAY_AMOUNT

        entry["score"] = max(0, entry["score"] - decay_total)
        entry["last_decay"] = now

    def add_event(self, ip, event_type, weight):

        entry = self._get_entry(ip)

        self.decay(ip)

        entry["score"] += weight
        entry["events"].append((event_type, time.time()))
        entry["last_seen"] = time.time()

        # keep bounded
        if len(entry["events"]) > self.MAX_EVENTS_PER_IP:
            entry["events"] = entry["events"][-self.MAX_EVENTS_PER_IP:]

        print(f"[RISK] {ip} score={entry['score']} (+{weight} from {event_type})")

        return entry["score"]

    def get_score(self, ip):
        entry = self._get_entry(ip)
        self.decay(ip)
        return entry["score"]

    def decision(self, ip):

        entry = self._get_entry(ip)
        self.decay(ip)

        score = entry["score"]

        if score >= self.BLOCK_THRESHOLD:
            return "BLOCK"

        if score >= self.SUSPICIOUS_THRESHOLD:
            return "SUSPICIOUS"

        return "ALLOW"

    def reset_ip(self, ip):
        if ip in self.state:
            del self.state[ip]

    def clear(self):
        self.state = {}
