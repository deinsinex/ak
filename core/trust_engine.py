import time


class TrustEngine:

    def __init__(self):

        self.trust = {}

        self.MAX_TRUST = 100
        self.MIN_TRUST = -100

    def increase(self, ip, amount=1):

        entry = self.trust.setdefault(ip, {"score": 0, "last": time.time()})

        entry["score"] = min(self.MAX_TRUST, entry["score"] + amount)
        entry["last"] = time.time()

    def decrease(self, ip, amount=10):

        entry = self.trust.setdefault(ip, {"score": 0, "last": time.time()})

        entry["score"] = max(self.MIN_TRUST, entry["score"] - amount)
        entry["last"] = time.time()

    def get(self, ip):

        entry = self.trust.get(ip)

        if not entry:
            return 0

        return entry["score"]
