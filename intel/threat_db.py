kkimport time


class ThreatDB:

    def __init__(self):

        # ip -> {score, last_seen}
        self.threat_map = {}

        self.BLOCK_THRESHOLD = 100

        # cleanup parameters
        self.CLEANUP_INTERVAL = 300
        self.EXPIRE_TIME = 3600
        self.last_cleanup = time.time()


    def add_score(self, ip, points):

        now = time.time()

        if ip not in self.threat_map:

            self.threat_map[ip] = {
                "score": 0,
                "last_seen": now
            }

        self.threat_map[ip]["score"] += points
        self.threat_map[ip]["last_seen"] = now

        score = self.threat_map[ip]["score"]

        print(f"⚠️ Threat score for {ip}: {score}")

        self._cleanup_if_needed()

        return score


    def should_block(self, ip):

        if ip not in self.threat_map:
            return False

        return self.threat_map[ip]["score"] >= self.BLOCK_THRESHOLD


    def get_ban_duration(self, ip):

        score = self.threat_map.get(ip, {}).get("score", 0)

        if score >= 200:
            return 1800   # 30 minutes

        elif score >= 150:
            return 900    # 15 minutes

        elif score >= 100:
            return 300    # 5 minutes

        else:
            return 60     # 1 minute


    def _cleanup_if_needed(self):

        now = time.time()

        if now - self.last_cleanup < self.CLEANUP_INTERVAL:
            return

        for ip in list(self.threat_map.keys()):

            last_seen = self.threat_map[ip]["last_seen"]

            if now - last_seen > self.EXPIRE_TIME:
                del self.threat_map[ip]

        self.last_cleanup = now
