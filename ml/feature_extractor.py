import time
import numpy as np
from collections import defaultdict

from scapy.layers.inet import IP, TCP


FLOW_WINDOW = 5
MIN_PACKETS = 5


class FlowStats:

    def __init__(self):

        self.packet_sizes = []
        self.timestamps = []
        self.ttl_values = []

        self.header_lengths = []
        self.payload_lengths = []
        self.window_sizes = []

        self.syn_count = 0
        self.rst_count = 0

        self.src_count = 0
        self.dst_count = 0


class FeatureExtractor:

    def __init__(self):

        self.flows = defaultdict(FlowStats)


    def update(self, packet):

        if not packet.haslayer(IP):
            return None

        ip = packet[IP]

        src = ip.src
        dst = ip.dst

        flow_key = (src, dst)

        stats = self.flows[flow_key]

        now = time.time()

        size = len(packet)

        stats.packet_sizes.append(size)
        stats.timestamps.append(now)
        stats.ttl_values.append(ip.ttl)

        stats.src_count += 1
        stats.dst_count += 1

        header_len = ip.ihl * 4 if ip.ihl else 0
        stats.header_lengths.append(header_len)

        if packet.haslayer(TCP):

            tcp = packet[TCP]

            payload_len = len(tcp.payload)
            stats.payload_lengths.append(payload_len)

            stats.window_sizes.append(tcp.window)

            flags = int(tcp.flags)

            if flags & 0x02:
                stats.syn_count += 1

            if flags & 0x04:
                stats.rst_count += 1

        else:

            stats.payload_lengths.append(0)
            stats.window_sizes.append(0)

        if len(stats.packet_sizes) < MIN_PACKETS:
            return None

        if now - stats.timestamps[0] < FLOW_WINDOW:
            return None

        return self.compute_features(flow_key)


    def compute_features(self, flow_key):

        stats = self.flows[flow_key]

        sizes = np.array(stats.packet_sizes)
        times = np.array(stats.timestamps)
        ttls = np.array(stats.ttl_values)

        headers = np.array(stats.header_lengths)
        payloads = np.array(stats.payload_lengths)
        windows = np.array(stats.window_sizes)

        deltas = np.diff(times)

        features = {

            "network_packet-size_avg": float(np.mean(sizes)),
            "network_packet-size_max": float(np.max(sizes)),
            "network_packet-size_min": float(np.min(sizes)),
            "network_packet-size_std_deviation": float(np.std(sizes)),

            "network_packets_all_count": int(len(sizes)),
            "network_packets_src_count": int(stats.src_count),
            "network_packets_dst_count": int(stats.dst_count),

            "network_time-delta_avg": float(np.mean(deltas)) if len(deltas) else 0,
            "network_time-delta_max": float(np.max(deltas)) if len(deltas) else 0,
            "network_time-delta_min": float(np.min(deltas)) if len(deltas) else 0,
            "network_time-delta_std_deviation": float(np.std(deltas)) if len(deltas) else 0,

            "network_ttl_avg": float(np.mean(ttls)),
            "network_ttl_max": float(np.max(ttls)),
            "network_ttl_min": float(np.min(ttls)),
            "network_ttl_std_deviation": float(np.std(ttls)),

            "network_header-length_avg": float(np.mean(headers)),
            "network_header-length_max": float(np.max(headers)),

            "network_payload-length_avg": float(np.mean(payloads)),
            "network_payload-length_max": float(np.max(payloads)),
            "network_payload-length_min": float(np.min(payloads)),
            "network_payload-length_std_deviation": float(np.std(payloads)),

            "network_tcp-flags_syn_count": int(stats.syn_count),
            "network_tcp-flags_rst_count": int(stats.rst_count),

            "network_window-size_max": float(np.max(windows)),
            "network_window-size_min": float(np.min(windows)),
            "network_window-size_std_deviation": float(np.std(windows)),
        }

        del self.flows[flow_key]

        return features
