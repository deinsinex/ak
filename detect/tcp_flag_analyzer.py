from scapy.layers.inet import TCP


class TCPFlagAnalyzer:

    def analyze(self, packet):

        if not packet.haslayer(TCP):
            return None

        flags = int(packet[TCP].flags)

        if flags == 0x00:
            return "NULL_SCAN"

        if flags == 0x01:
            return "FIN_SCAN"

        if flags == 0x29:
            return "XMAS_SCAN"

        return None
