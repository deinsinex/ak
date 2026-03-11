import time
import numpy as np
from collections import defaultdict

from scapy.layers.inet import IP, TCP


FLOW_WINDOW = 5   # seconds
MIN_PACKETS = 5


class FlowStats:

    def __init__(self):
        self.packet_sizes = []
        self.timestamps = []
        self.ttl_values = []

        self.header_lengths = []
        self.payload_lengths = []
        self.window_sizes = []
        self.mss_values = []

        self.tcp_flag_values = []

        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.psh_count = 0
        self.rst_count = 0
        self.urg_count = 0

        self.fragmented_packets = 0

        self.src_count = 0
        self.dst_count = 0


class FlowAnalyzer:

    def __init__(self):
        # flow_key -> FlowStats
        self.flows = defaultdict(FlowStats)

    def update(self, packet):
        """
        Update flow statistics with a live packet.
        Returns:
            dict (51 features) when flow window matures
            None otherwise
        """

        if not packet.haslayer(IP):
            return None

        ip = packet[IP]

        src = ip.src
        dst = ip.dst
        flow_key = (src, dst)

        stats = self.flows[flow_key]
        now = time.time()

        packet_size = len(packet)

        stats.packet_sizes.append(packet_size)
        stats.timestamps.append(now)
        stats.ttl_values.append(int(ip.ttl) if ip.ttl is not None else 0)

        # For this flow, src_count and dst_count are packet counters.
        # Since flow_key is directional, both increment together.
        stats.src_count += 1
        stats.dst_count += 1

        # -----------------------------
        # IP header length
        # -----------------------------
        ip_header_len = (ip.ihl * 4) if getattr(ip, "ihl", None) else 0
        stats.header_lengths.append(ip_header_len)

        # -----------------------------
        # Fragmentation
        # -----------------------------
        try:
            if int(ip.frag) > 0 or int(ip.flags) & 0x1:
                stats.fragmented_packets += 1
        except Exception:
            pass

        # -----------------------------
        # TCP-specific features
        # -----------------------------
        if packet.haslayer(TCP):
            tcp = packet[TCP]

            # Payload length
            try:
                payload_len = len(bytes(tcp.payload))
            except Exception:
                payload_len = 0

            stats.payload_lengths.append(payload_len)

            # Window size
            try:
                stats.window_sizes.append(int(tcp.window))
            except Exception:
                stats.window_sizes.append(0)

            # TCP flags
            try:
                flags_int = int(tcp.flags)
            except Exception:
                flags_int = 0

            stats.tcp_flag_values.append(flags_int)

            if flags_int & 0x02:
                stats.syn_count += 1
            if flags_int & 0x10:
                stats.ack_count += 1
            if flags_int & 0x01:
                stats.fin_count += 1
            if flags_int & 0x08:
                stats.psh_count += 1
            if flags_int & 0x04:
                stats.rst_count += 1
            if flags_int & 0x20:
                stats.urg_count += 1

            # MSS from TCP options
            mss = 0
            try:
                for option in tcp.options:
                    if isinstance(option, tuple) and len(option) == 2:
                        if option[0] == "MSS":
                            mss = int(option[1])
                            break
            except Exception:
                mss = 0

            stats.mss_values.append(mss)

        else:
            # Non-TCP packets still need safe placeholders
            stats.payload_lengths.append(0)
            stats.window_sizes.append(0)
            stats.tcp_flag_values.append(0)
            stats.mss_values.append(0)

        # -----------------------------
        # Flow maturity check
        # -----------------------------
        if len(stats.packet_sizes) < MIN_PACKETS:
            return None

        if (now - stats.timestamps[0]) < FLOW_WINDOW:
            return None

        return self.compute_features(flow_key)

    def compute_features(self, flow_key):
        """
        Compute EXACT 51-feature vector expected by training/model_metadata.json
        """

        stats = self.flows[flow_key]

        sizes = np.array(stats.packet_sizes, dtype=float)
        times = np.array(stats.timestamps, dtype=float)
        ttls = np.array(stats.ttl_values, dtype=float)

        headers = np.array(stats.header_lengths, dtype=float)
        payloads = np.array(stats.payload_lengths, dtype=float)
        windows = np.array(stats.window_sizes, dtype=float)
        mss_vals = np.array(stats.mss_values, dtype=float)
        tcp_flags = np.array(stats.tcp_flag_values, dtype=float)

        deltas = np.diff(times)

        # -----------------------------
        # Helper functions
        # -----------------------------
        def avg(arr):
            return float(np.mean(arr)) if len(arr) else 0.0

        def mx(arr):
            return float(np.max(arr)) if len(arr) else 0.0

        def mn(arr):
            return float(np.min(arr)) if len(arr) else 0.0

        def std(arr):
            return float(np.std(arr)) if len(arr) else 0.0

        # -----------------------------
        # Approximate "log_*" features
        # These are dataset-style features not directly available
        # from raw packets, so we derive stable approximations.
        # -----------------------------
        # Use payload lengths as "data ranges"
        log_data_ranges = payloads.copy()

        # Count distinct coarse payload size buckets as "data types"
        payload_buckets = set(int(p // 64) for p in payloads) if len(payloads) else set()

        # Message interval approximated by packet time delta
        avg_message_interval = avg(deltas)

        # Message count approximated by packet count in flow
        message_count = int(len(sizes))

        # -----------------------------
        # Fragmentation score
        # -----------------------------
        total_packets = len(sizes)
        fragmentation_score = (
            float(stats.fragmented_packets / total_packets)
            if total_packets > 0 else 0.0
        )

        # -----------------------------
        # Build EXACT feature dict
        # -----------------------------
        features = {
            # 1-4 log_data-ranges_*
            "log_data-ranges_avg": avg(log_data_ranges),
            "log_data-ranges_max": mx(log_data_ranges),
            "log_data-ranges_min": mn(log_data_ranges),
            "log_data-ranges_std_deviation": std(log_data_ranges),

            # 5-7 log_* counts/intervals
            "log_data-types_count": int(len(payload_buckets)),
            "log_interval-messages": avg_message_interval,
            "log_messages_count": int(message_count),

            # 8-9 fragmentation
            "network_fragmentation-score": fragmentation_score,
            "network_fragmented-packets": int(stats.fragmented_packets),

            # 10-13 header length
            "network_header-length_avg": avg(headers),
            "network_header-length_max": mx(headers),
            "network_header-length_min": mn(headers),
            "network_header-length_std_deviation": std(headers),

            # 14 interval packets
            "network_interval-packets": avg(deltas),

            # 15-18 MSS
            "network_mss_avg": avg(mss_vals),
            "network_mss_max": mx(mss_vals),
            "network_mss_min": mn(mss_vals),
            "network_mss_std_deviation": std(mss_vals),

            # 19-22 packet size
            "network_packet-size_avg": avg(sizes),
            "network_packet-size_max": mx(sizes),
            "network_packet-size_min": mn(sizes),
            "network_packet-size_std_deviation": std(sizes),

            # 23-25 packet counts
            "network_packets_all_count": int(total_packets),
            "network_packets_dst_count": int(stats.dst_count),
            "network_packets_src_count": int(stats.src_count),

            # 26-29 payload length
            "network_payload-length_avg": avg(payloads),
            "network_payload-length_max": mx(payloads),
            "network_payload-length_min": mn(payloads),
            "network_payload-length_std_deviation": std(payloads),

            # 30-34 TCP flag counts
            "network_tcp-flags-ack_count": int(stats.ack_count),
            "network_tcp-flags-fin_count": int(stats.fin_count),
            "network_tcp-flags-psh_count": int(stats.psh_count),
            "network_tcp-flags-rst_count": int(stats.rst_count),
            "network_tcp-flags-syn_count": int(stats.syn_count),

            # 35 urg
            "network_tcp-flags-urg_count": int(stats.urg_count),

            # 36-39 TCP flag numeric distribution
            "network_tcp-flags_avg": avg(tcp_flags),
            "network_tcp-flags_max": mx(tcp_flags),
            "network_tcp-flags_min": mn(tcp_flags),
            "network_tcp-flags_std_deviation": std(tcp_flags),

            # 40-43 time deltas
            "network_time-delta_avg": avg(deltas),
            "network_time-delta_max": mx(deltas),
            "network_time-delta_min": mn(deltas),
            "network_time-delta_std_deviation": std(deltas),

            # 44-47 TTL
            "network_ttl_avg": avg(ttls),
            "network_ttl_max": mx(ttls),
            "network_ttl_min": mn(ttls),
            "network_ttl_std_deviation": std(ttls),

            # 48-51 window size
            "network_window-size_avg": avg(windows),
            "network_window-size_max": mx(windows),
            "network_window-size_min": mn(windows),
            "network_window-size_std_deviation": std(windows),
        }

        # Cleanup mature flow after extracting features
        del self.flows[flow_key]

        return features
