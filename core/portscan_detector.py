import time
from collections import defaultdict, deque


class PortScanDetector:
    def __init__(self, window_seconds=10, unique_port_threshold=8, event_threshold=15):
        self.window_seconds = window_seconds
        self.unique_port_threshold = unique_port_threshold
        self.event_threshold = event_threshold
        self.events = defaultdict(deque)

    def observe(self, src_ip, dst_port):
        now = time.time()
        q = self.events[src_ip]
        q.append((now, dst_port))

        while q and (now - q[0][0]) > self.window_seconds:
            q.popleft()

        ports = {p for _, p in q if p is not None}
        count = len(q)

        # Stronger rule:
        # must hit MANY distinct ports OR many events on non-web ports
        if len(ports) >= self.unique_port_threshold:
            return True, count, len(ports)

        suspicious_non_web = [p for _, p in q if p not in {53, 80, 443, 123, None}]
        if len(suspicious_non_web) >= self.event_threshold:
            return True, count, len(ports)

        return False, count, len(ports)

    def reset_ip(self, ip):
        self.events.pop(ip, None)
