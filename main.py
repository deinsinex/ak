from capture.scapy_sniffer import start_sniffer

from detect.payload_inspector import PayloadInspector
from detect.scan_detector import ScanDetector
from detect.tcp_flag_analyzer import TCPFlagAnalyzer

from decision.block_engine import BlockEngine
from intel.threat_db import ThreatDB
from intel.threat_memory import ThreatMemory

from core.telemetry import Telemetry
from core.risk_engine import RiskEngine
from core.baseline_engine import BaselineEngine
from core.protocol_analyzer import ProtocolAnalyzer
from core.attack_sequence_engine import AttackSequenceEngine
from core.flow_analyzer import FlowAnalyzer
from core.threat_intel_engine import ThreatIntelEngine
from core.traffic_monitor import TrafficMonitor
from core.trust_engine import TrustEngine
from core.collaborative_intel import CollaborativeIntel
from core.threat_share import share_threat
from core.firewall_control import FirewallControl

from ml.ml_detector import MLDetector

from federation.update_client import fetch_global_model
from visualization.dashboard_server import start_attack_dashboard

import threading
import time


print("\n🛡️ Aegis AI Firewall Starting...\n")


payload_inspector = PayloadInspector()
scan_detector = ScanDetector()
tcp_analyzer = TCPFlagAnalyzer()

protocol_analyzer = ProtocolAnalyzer()

flow_analyzer = FlowAnalyzer()
ml_detector = MLDetector()

block_engine = BlockEngine()
threat_db = ThreatDB()
threat_memory = ThreatMemory()

telemetry = Telemetry()

risk_engine = RiskEngine()
baseline_engine = BaselineEngine()

sequence_engine = AttackSequenceEngine()

threat_intel = ThreatIntelEngine()

traffic_monitor = TrafficMonitor()

trust_engine = TrustEngine()

collab_intel = CollaborativeIntel()

firewall_control = FirewallControl()


threading.Thread(
    target=start_attack_dashboard,
    daemon=True
).start()


def model_update_loop():

    while True:

        try:
            fetch_global_model()
        except Exception as e:
            print("Federated update error:", e)

        time.sleep(300)


threading.Thread(
    target=model_update_loop,
    daemon=True
).start()


def respond_to_threat(ip, reason):

    duration = threat_db.get_ban_duration(ip)

    telemetry.log("BLOCKED_ATTACKER", ip, reason)

    if firewall_control.is_protection_enabled():

        block_engine.block_ip(ip, duration)

        share_threat(ip, reason)

        print(f"🔥 BLOCKED {ip}")

    else:

        print(f"⚠️ DETECTED {ip} (blocking disabled)")


def register_event(ip, event_name, weight):

    traffic_monitor.record_attack()

    trust_engine.record_attack(ip)

    sequence_engine.record_event(ip, event_name)

    seq = sequence_engine.detect_sequence(ip)

    if seq:
        risk_engine.add_event(ip, "ATTACK_SEQUENCE", 80)

    risk_engine.add_event(ip, event_name, weight)

    decision = risk_engine.decision(ip)

    if decision == "BLOCK":

        respond_to_threat(ip, event_name)


def detection_engine(event):

    ip = event.source_ip
    packet = event.raw_packet

    traffic_monitor.record_packet(ip)

    if collab_intel.is_known_bad(ip):

        respond_to_threat(ip, "THREAT_FEED")
        return

    if trust_engine.is_untrusted(ip):

        respond_to_threat(ip, "LOW_TRUST")
        return

    intel = threat_intel.lookup(ip)

    if intel.get("malicious"):

        respond_to_threat(ip, "THREAT_INTEL")
        return

    anomaly = tcp_analyzer.analyze(packet)

    if anomaly:

        register_event(ip, anomaly, 50)
        return

    if scan_detector.analyze(event):

        register_event(ip, "PORT_SCAN", 40)
        return

    if payload_inspector.inspect(event.payload):

        register_event(ip, "PAYLOAD_ATTACK", 60)
        return

    features = flow_analyzer.update(packet)

    if not features:

        trust_engine.record_benign(ip)
        return

    result = ml_detector.analyze(features)

    if result["is_attack"]:

        register_event(ip, "ML_ATTACK", 80)
        return

    trust_engine.record_benign(ip)


start_sniffer(detection_engine)
