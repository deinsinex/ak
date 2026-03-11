import time
from collections import defaultdict


class TrafficMonitor:

    def __init__(self):

        self.packet_counter = 0
        self.attack_counter = 0

        self.ip_counter = defaultdict(int)

        self.start_time = time.time()

        self.history = []


    def record_packet(self, ip):

        self.packet_counter += 1

        self.ip_counter[ip] += 1


    def record_attack(self):

        self.attack_counter += 1


    def stats(self):

        now = time.time()

        elapsed = now - self.start_time

        if elapsed == 0:
            elapsed = 1

        packets_per_sec = self.packet_counter / elapsed

        active_ips = len(self.ip_counter)

        return {

            "packets_per_sec": round(packets_per_sec, 2),

            "total_packets": self.packet_counter,

            "attack_events": self.attack_counter,

            "active_ips": active_ips
        }


    def snapshot(self):

        stats = self.stats()

        stats["timestamp"] = time.time()

        self.history.append(stats)

        if len(self.history) > 1000:
            self.history.pop(0)

        return stats
