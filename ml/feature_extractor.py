import time
import json
import os
import numpy as np
from collections import defaultdict

from scapy.layers.inet import IP, TCP


FLOW_WINDOW = 5
MIN_PACKETS = 5
MODEL_METADATA_FILE = "training/model_metadata.json"


class FlowStats:

    def __init__(self):

        self.packet_sizes = []
        self.timestamps = []
        self.ttl_values = []

        self.header_lengths = []
        self.payload_lengths = []
        self.window_sizes = []
        self.mss_values = []

        self.tcp_flags = []

        self.syn_count = 0
        self.fin_count = 0
        self.psh_count = 0
        self.rst_count = 0
        self.ack_count = 0
        self.urg_count = 0

        self.src_count = 0
        self.dst_count = 0

        self.protocols = set()
        self.ports_src = set()
        self.ports_dst = set()

        self.fragmented_packets = 0


class FeatureExtractor:

    def __init__(self):

        self.flows = defaultdict(FlowStats)
        self.feature_names = self._load_feature_names()

    def _load_feature_names(self):
        if not os.path.exists(MODEL_METADATA_FILE):
            raise FileNotFoundError(f"Missing model metadata: {MODEL_METADATA_FILE}")

        with open(MODEL_METADATA_FILE, "r") as f:
            data = json.load(f)

        feature_names = data.get("feature_names")

        if not feature_names or not isinstance(feature_names, list):
            raise ValueError("Invalid model_metadata.json: missing feature_names")

        return feature_names

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

        # IP fragmentation
        if getattr(ip, "frag", 0) > 0 or getattr(ip, "flags", 0) != 0:
            stats.fragmented_packets += 1

        # Protocol tracking
        stats.protocols.add(int(ip.proto))

        if packet.haslayer(TCP):

            tcp = packet[TCP]

            payload_len = len(bytes(tcp.payload))
            stats.payload_lengths.append(payload_len)

            stats.window_sizes.append(tcp.window)

            # ports
            stats.ports_src.add(int(tcp.sport))
            stats.ports_dst.add(int(tcp.dport))

            # MSS option if present
            mss_value = 0
            try:
                for opt in tcp.options:
                    if isinstance(opt, tuple) and len(opt) >= 2 and opt[0] == "MSS":
                        mss_value = int(opt[1])
                        break
            except Exception:
                pass

            stats.mss_values.append(mss_value)

            flags = int(tcp.flags)
            stats.tcp_flags.append(flags)

            if flags & 0x02:
                stats.syn_count += 1
            if flags & 0x01:
                stats.fin_count += 1
            if flags & 0x08:
                stats.psh_count += 1
            if flags & 0x04:
                stats.rst_count += 1
            if flags & 0x10:
                stats.ack_count += 1
            if flags & 0x20:
                stats.urg_count += 1

        else:

            stats.payload_lengths.append(0)
            stats.window_sizes.append(0)
            stats.mss_values.append(0)
            stats.tcp_flags.append(0)

        if len(stats.packet_sizes) < MIN_PACKETS:
            return None

        if now - stats.timestamps[0] < FLOW_WINDOW:
            return None

        return self.compute_features(flow_key)

    def _safe_stats(self, arr):
        if len(arr) == 0:
            return 0.0, 0.0, 0.0, 0.0

        arr = np.array(arr, dtype=float)

        return (
            float(np.mean(arr)),
            float(np.max(arr)),
            float(np.min(arr)),
            float(np.std(arr))
        )

    def compute_features(self, flow_key):

        stats = self.flows[flow_key]

        sizes = np.array(stats.packet_sizes, dtype=float)
        times = np.array(stats.timestamps, dtype=float)
        ttls = np.array(stats.ttl_values, dtype=float)

        headers = np.array(stats.header_lengths, dtype=float)
        payloads = np.array(stats.payload_lengths, dtype=float)
        windows = np.array(stats.window_sizes, dtype=float)
        mss_vals = np.array(stats.mss_values, dtype=float)
        tcp_flags = np.array(stats.tcp_flags, dtype=float)

        deltas = np.diff(times)

        packet_avg, packet_max, packet_min, packet_std = self._safe_stats(sizes)
        delta_avg, delta_max, delta_min, delta_std = self._safe_stats(deltas)
        ttl_avg, ttl_max, ttl_min, ttl_std = self._safe_stats(ttls)
        header_avg, header_max, header_min, header_std = self._safe_stats(headers)
        payload_avg, payload_max, payload_min, payload_std = self._safe_stats(payloads)
        window_avg, window_max, window_min, window_std = self._safe_stats(windows)
        mss_avg, mss_max, mss_min, mss_std = self._safe_stats(mss_vals)
        tcpf_avg, tcpf_max, tcpf_min, tcpf_std = self._safe_stats(tcp_flags)

        fragmented_count = int(stats.fragmented_packets)
        fragmentation_score = (
            float(fragmented_count / len(sizes)) if len(sizes) > 0 else 0.0
        )

        # Build exact 51-feature schema
        features = {name: 0.0 for name in self.feature_names}

        # Log features (not available in live packet-only mode -> keep 0 unless count can be approximated)
        features["log_data-ranges_avg"] = 0.0
        features["log_data-ranges_max"] = 0.0
        features["log_data-ranges_min"] = 0.0
        features["log_data-ranges_std_deviation"] = 0.0
        features["log_data-types_count"] = 0.0
        features["log_interval-messages"] = 0.0
        features["log_messages_count"] = 0.0

        # Network fragmentation
        features["network_fragmentation-score"] = fragmentation_score
        features["network_fragmented-packets"] = fragmented_count

        # Header length
        features["network_header-length_avg"] = header_avg
        features["network_header-length_max"] = header_max
        features["network_header-length_min"] = header_min
        features["network_header-length_std_deviation"] = header_std

        # Packet interval
        features["network_interval-packets"] = float(len(sizes))

        # MSS
        features["network_mss_avg"] = mss_avg
        features["network_mss_max"] = mss_max
        features["network_mss_min"] = mss_min
        features["network_mss_std_deviation"] = mss_std

        # Packet size
        features["network_packet-size_avg"] = packet_avg
        features["network_packet-size_max"] = packet_max
        features["network_packet-size_min"] = packet_min
        features["network_packet-size_std_deviation"] = packet_std

        # Packet counts
        features["network_packets_all_count"] = float(len(sizes))
        features["network_packets_dst_count"] = float(stats.dst_count)
        features["network_packets_src_count"] = float(stats.src_count)

        # Payload length
        features["network_payload-length_avg"] = payload_avg
        features["network_payload-length_max"] = payload_max
        features["network_payload-length_min"] = payload_min
        features["network_payload-length_std_deviation"] = payload_std

        # TCP flag counts (EXACT names from metadata)
        features["network_tcp-flags-ack_count"] = float(stats.ack_count)
        features["network_tcp-flags-fin_count"] = float(stats.fin_count)
        features["network_tcp-flags-psh_count"] = float(stats.psh_count)
        features["network_tcp-flags-rst_count"] = float(stats.rst_count)
        features["network_tcp-flags-syn_count"] = float(stats.syn_count)
        features["network_tcp-flags-urg_count"] = float(stats.urg_count)

        # TCP flag aggregate stats
        features["network_tcp-flags_avg"] = tcpf_avg
        features["network_tcp-flags_max"] = tcpf_max
        features["network_tcp-flags_min"] = tcpf_min
        features["network_tcp-flags_std_deviation"] = tcpf_std

        # Time delta
        features["network_time-delta_avg"] = delta_avg
        features["network_time-delta_max"] = delta_max
        features["network_time-delta_min"] = delta_min
        features["network_time-delta_std_deviation"] = delta_std

        # TTL
        features["network_ttl_avg"] = ttl_avg
        features["network_ttl_max"] = ttl_max
        features["network_ttl_min"] = ttl_min
        features["network_ttl_std_deviation"] = ttl_std

        # Window size
        features["network_window-size_avg"] = window_avg
        features["network_window-size_max"] = window_max
        features["network_window-size_min"] = window_min
        features["network_window-size_std_deviation"] = window_std

        # Keep only exact metadata order
        ordered_features = {
            name: float(features.get(name, 0.0))
            for name in self.feature_names
        }

        del self.flows[flow_key]

        return ordered_features
