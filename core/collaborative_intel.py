import threading
import time

from core.threat_share import fetch_threat_feed


class CollaborativeIntel:

    def __init__(self):

        self.intel = {}

        thread = threading.Thread(
            target=self.update_loop,
            daemon=True
        )

        thread.start()

    def update_loop(self):

        while True:

            try:

                data = fetch_threat_feed()

                if isinstance(data, dict):

                    self.intel = data

                    print("Threat feed updated:", len(data))

            except Exception as e:

                print("Intel update error:", e)

            time.sleep(60)

    def is_known_bad(self, ip):

        return ip in self.intel
