import time
from collections import deque


class TrafficMonitor:

    def __init__(self):

        self.packet_times = deque()

        self.WINDOW = 10   # seconds

    def record_packet(self):

        now = time.time()

        self.packet_times.append(now)

        while self.packet_times and now - self.packet_times[0] > self.WINDOW:
            self.packet_times.popleft()

    def get_rate(self):

        now = time.time()

        while self.packet_times and now - self.packet_times[0] > self.WINDOW:
            self.packet_times.popleft()

        return len(self.packet_times)
