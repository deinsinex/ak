from scapy.all import sniff, IP, Raw
import traceback


class PacketEvent:

    def __init__(self, source_ip, destination_ip, protocol, payload, raw_packet):

        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.protocol = protocol
        self.payload = payload
        self.raw_packet = raw_packet


def start_sniffer(callback, iface=None, debug=False):

    """
    Start packet capture and send events into the firewall detection pipeline.
    """

    def process_packet(packet):

        try:

            if not packet.haslayer(IP):
                return

            ip_layer = packet[IP]

            payload_bytes = None

            if packet.haslayer(Raw):
                payload_bytes = bytes(packet[Raw].load)

            event = PacketEvent(
                source_ip=ip_layer.src,
                destination_ip=ip_layer.dst,
                protocol=ip_layer.proto,
                payload=payload_bytes,
                raw_packet=packet
            )

            if debug:
                print(f"[PACKET] {event.source_ip} → {event.destination_ip}")

            callback(event)

        except Exception:
            print("Packet processing error:")
            traceback.print_exc()


    print("\n📡 Packet sniffer starting...")

    if iface:
        print(f"Interface: {iface}")
    else:
        print("Interface: default")

    sniff(
        iface=iface,
        prn=process_packet,
        store=False,
        filter="ip"
    )
