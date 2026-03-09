from scapy.layers.inet import TCP, UDP


class ProtocolAnalyzer:

    def analyze(self, packet):

        protocol_info = {
            "protocol": "UNKNOWN",
            "port": None
        }

        if packet.haslayer(TCP):

            tcp = packet[TCP]
            port = tcp.dport

            protocol_info["port"] = port

            if port == 80:
                protocol_info["protocol"] = "HTTP"

            elif port == 443:
                protocol_info["protocol"] = "HTTPS"

            elif port == 22:
                protocol_info["protocol"] = "SSH"

            elif port == 21:
                protocol_info["protocol"] = "FTP"

            else:
                protocol_info["protocol"] = "TCP_OTHER"


        elif packet.haslayer(UDP):

            udp = packet[UDP]
            port = udp.dport

            protocol_info["port"] = port

            if port == 53:
                protocol_info["protocol"] = "DNS"

            elif port == 123:
                protocol_info["protocol"] = "NTP"

            else:
                protocol_info["protocol"] = "UDP_OTHER"


        return protocol_info
