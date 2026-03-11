import time


class TrustEngine:

    def __init__(self):

        self.trust_scores = {}
        self.last_seen = {}

        self.MAX_TRUST = 100
        self.MIN_TRUST = 0


    def get_trust(self, ip):

        return self.trust_scores.get(ip, 50)


    def record_benign(self, ip):

        score = self.trust_scores.get(ip, 50)

        score += 1

        if score > self.MAX_TRUST:
            score = self.MAX_TRUST

        self.trust_scores[ip] = score
        self.last_seen[ip] = time.time()


    def record_suspicious(self, ip):

        score = self.trust_scores.get(ip, 50)

        score -= 10

        if score < self.MIN_TRUST:
            score = self.MIN_TRUST

        self.trust_scores[ip] = score
        self.last_seen[ip] = time.time()


    def record_attack(self, ip):

        score = self.trust_scores.get(ip, 50)

        score -= 30

        if score < self.MIN_TRUST:
            score = self.MIN_TRUST

        self.trust_scores[ip] = score
        self.last_seen[ip] = time.time()


    def is_untrusted(self, ip):

        score = self.get_trust(ip)

        return score < 20
