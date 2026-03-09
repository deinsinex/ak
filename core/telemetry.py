import json
import time
import os
import requests
import threading


MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
MAX_GEO_CACHE = 5000


class Telemetry:

    def __init__(self, logfile="logs/attacks.json"):

        self.logfile = logfile

        self.geo_cache = {}

        self.lock = threading.Lock()

        os.makedirs("logs", exist_ok=True)

        if not os.path.exists(self.logfile):
            open(self.logfile, "w").close()


    def rotate_logs(self):

        if os.path.getsize(self.logfile) > MAX_LOG_SIZE:

            timestamp = int(time.time())

            new_name = f"logs/attacks_{timestamp}.json"

            os.rename(self.logfile, new_name)

            open(self.logfile, "w").close()


    def geo_lookup(self, ip):

        if ip in self.geo_cache:
            return self.geo_cache[ip]

        try:

            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                timeout=2
            )

            data = response.json()

            if data.get("status") != "success":
                return None

            geo = {
                "country": data.get("country"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon")
            }

            if len(self.geo_cache) > MAX_GEO_CACHE:
                self.geo_cache.clear()

            self.geo_cache[ip] = geo

            return geo

        except Exception:

            return None


    def log(self, event_type, ip, action):

        geo = self.geo_lookup(ip)

        entry = {

            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),

            "event": event_type,

            "ip": ip,

            "action": action,

            "geo": geo
        }

        print(f"📡 TELEMETRY → {entry}")

        try:

            with self.lock:

                self.rotate_logs()

                with open(self.logfile, "a") as f:
                    f.write(json.dumps(entry) + "\n")

        except Exception as e:

            print("Telemetry write error:", e)
