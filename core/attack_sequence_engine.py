import time
from collections import defaultdict


class AttackSequenceEngine:

    def __init__(self):

        # Track per-IP attack events
        self.events = defaultdict(list)

        # Time window to correlate attacks (seconds)
        self.WINDOW = 60

        # Known attack sequences
        self.sequences = [
            ["PORT_SCAN", "PAYLOAD_ATTACK"],
            ["PORT_SCAN", "ML_ATTACK"],
            ["PORT_SCAN", "TCP_SCAN"],
            ["PAYLOAD_ATTACK", "ML_ATTACK"]
        ]

    def record_event(self, ip, event):

        now = time.time()

        self.events[ip].append((event, now))

        # Remove old events
        self.events[ip] = [
            (e, t) for e, t in self.events[ip]
            if now - t < self.WINDOW
        ]

    def detect_sequence(self, ip):

        event_list = [e for e, t in self.events[ip]]

        for sequence in self.sequences:

            if all(event in event_list for event in sequence):

                return sequence

        return None
