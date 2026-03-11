import requests
import time


CACHE_TTL = 3600


class ThreatIntelEngine:

    def __init__(self):

        self.cache = {}

        self.local_blacklist = {
            "185.220.101.1",   # example TOR node
            "45.95.147.10"
        }


    def lookup(self, ip):

        # local blacklist
        if ip in self.local_blacklist:
            return {
                "malicious": True,
                "source": "local_blacklist"
            }

        now = time.time()

        if ip in self.cache:

            entry = self.cache[ip]

            if now - entry["time"] < CACHE_TTL:
                return entry["result"]

        result = self.query_abuseipdb(ip)

        self.cache[ip] = {
            "time": now,
            "result": result
        }

        return result


    def query_abuseipdb(self, ip):

        try:

            url = f"https://api.abuseipdb.com/api/v2/check"

            headers = {
                "Accept": "application/json",
                "Key": "demo_key"
            }

            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90
            }

            r = requests.get(url, headers=headers, params=params, timeout=3)

            if r.status_code != 200:
                return {"malicious": False}

            data = r.json()

            score = data["data"]["abuseConfidenceScore"]

            if score > 70:
                return {
                    "malicious": True,
                    "score": score,
                    "source": "abuseipdb"
                }

        except Exception:
            pass

        return {"malicious": False}
