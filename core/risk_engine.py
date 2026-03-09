import time


class RiskEngine:

    def __init__(self):

        # ip -> state
        self.state = {}

        self.SCORE_DECAY_INTERVAL = 60
        self.DECAY_AMOUNT = 5

        self.BLOCK_THRESHOLD = 100
        self.SUSPICIOUS_THRESHOLD = 50

    def _get_entry(self, ip):

        if ip not in self.state:

            self.state[ip] = {
                "score": 0,
                "events": [],
                "last_seen": time.time(),
                "last_decay": time.time()
            }

        return self.state[ip]

    def decay(self, ip):

        entry = self._get_entry(ip)

        now = time.time()

        if now - entry["last_decay"] >= self.SCORE_DECAY_INTERVAL:

            entry["score"] = max(0, entry["score"] - self.DECAY_AMOUNT)
            entry["last_decay"] = now

    def add_event(self, ip, event_type, weight):

        entry = self._get_entry(ip)

        self.decay(ip)

        entry["score"] += weight
        entry["events"].append((event_type, time.time()))
        entry["last_seen"] = time.time()

        print(f"[RISK] {ip} score={entry['score']} (+{weight} from {event_type})")

        return entry["score"]

    def decision(self, ip):

        entry = self._get_entry(ip)

        score = entry["score"]

        if score >= self.BLOCK_THRESHOLD:
            return "BLOCK"

        if score >= self.SUSPICIOUS_THRESHOLD:
            return "SUSPICIOUS"

        return "ALLOW"
