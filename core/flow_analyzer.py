import time
import numpy as np
from collections import defaultdict
from scapy.layers.inet import IP, TCP


FLOW_TIMEOUT = 8
MAX_PACKETS = 500


class FlowStats:

    def __init__(self):

        self.start_time = time.time()
        self.last_time = self.start_time

        self.packet_sizes = []
        self.timestamps = []

        self.forward_packets = 0
        self.backward_packets = 0

        self.forward_bytes = 0
        self.backward_bytes = 0

        self.src_ip = None
        self.dst_ip = None


class FlowAnalyzer:

    def __init__(self):

        self.flows = defaultdict(FlowStats)


    def update(self, packet):

        if not packet.haslayer(IP):
            return None

        ip = packet[IP]

        src = ip.src
        dst = ip.dst

        key = tuple(sorted([src, dst]))

        flow = self.flows[key]

        now = time.time()

        if flow.src_ip is None:
            flow.src_ip = src
            flow.dst_ip = dst

        size = len(packet)

        flow.packet_sizes.append(size)
        flow.timestamps.append(now)

        flow.last_time = now

        if src == flow.src_ip:
            flow.forward_packets += 1
            flow.forward_bytes += size
        else:
            flow.backward_packets += 1
            flow.backward_bytes += size

        if len(flow.packet_sizes) >= MAX_PACKETS:
            return self.compute_features(key)

        if now - flow.start_time > FLOW_TIMEOUT:
            return self.compute_features(key)

        return None


    def compute_features(self, key):

        flow = self.flows[key]

        duration = flow.last_time - flow.start_time

        sizes = np.array(flow.packet_sizes)
        times = np.array(flow.timestamps)

        deltas = np.diff(times) if len(times) > 1 else np.array([0])

        total_packets = flow.forward_packets + flow.backward_packets
        total_bytes = flow.forward_bytes + flow.backward_bytes

        avg_packet_size = np.mean(sizes)

        packet_rate = total_packets / duration if duration > 0 else 0
        byte_rate = total_bytes / duration if duration > 0 else 0

        packet_symmetry = 1 - abs(flow.forward_packets - flow.backward_packets) / max(total_packets,1)
        byte_symmetry = 1 - abs(flow.forward_bytes - flow.backward_bytes) / max(total_bytes,1)

        inter_mean = np.mean(deltas)
        inter_std = np.std(deltas)

        entropy = -np.sum(
            (sizes/np.sum(sizes)) * np.log2(sizes/np.sum(sizes)+1e-9)
        )

        features = {

            "flow_duration": duration,

            "packet_count": total_packets,

            "bytes_sent": flow.forward_bytes,
            "bytes_received": flow.backward_bytes,

            "avg_packet_size": avg_packet_size,

            "packet_rate": packet_rate,
            "byte_rate": byte_rate,

            "forward_packet_ratio": flow.forward_packets / max(total_packets,1),
            "byte_ratio": flow.forward_bytes / max(total_bytes,1),

            "packet_symmetry": packet_symmetry,
            "byte_symmetry": byte_symmetry,

            "inter_arrival_mean": inter_mean,
            "inter_arrival_std": inter_std,

            "packet_entropy": entropy
        }

        del self.flows[key]

        return features
