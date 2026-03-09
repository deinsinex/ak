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
from core.traffic_monitor import TrafficMonitor
from core.trust_engine import TrustEngine

from ml.feature_extractor import FeatureExtractor
from ml.ml_detector import MLDetector

from federation.update_client import fetch_global_model
from visualization.dashboard_server import start_attack_dashboard

import threading
import time


print("\n🛡️ Aegis AI Firewall Starting...\n")


# =============================
# INITIALIZE ENGINES
# =============================

payload_inspector = PayloadInspector()
scan_detector = ScanDetector()
tcp_analyzer = TCPFlagAnalyzer()

feature_extractor = FeatureExtractor()
ml_detector = MLDetector()

protocol_analyzer = ProtocolAnalyzer()

block_engine = BlockEngine()
threat_db = ThreatDB()
threat_memory = ThreatMemory()

telemetry = Telemetry()

risk_engine = RiskEngine()
baseline_engine = BaselineEngine()

sequence_engine = AttackSequenceEngine()

traffic_monitor = TrafficMonitor()

trust_engine = TrustEngine()


# =============================
# START DASHBOARD
# =============================

threading.Thread(
    target=start_attack_dashboard,
    daemon=True
).start()


# =============================
# FEDERATED MODEL UPDATER
# =============================

def model_update_loop():

    while True:

        print("Checking for global model update...")

        try:
            fetch_global_model()
        except Exception as e:
            print("Federated update error:", e)

        time.sleep(300)


threading.Thread(
    target=model_update_loop,
    daemon=True
).start()


# =============================
# RESPONSE ENGINE
# =============================

def respond_to_threat(ip):

    decision = risk_engine.decision(ip)

    trust = trust_engine.get(ip)

    print(f"[TRUST] {ip} → {trust}")

    if decision == "BLOCK" and trust < 20:

        duration = threat_db.get_ban_duration(ip)

        telemetry.log("BLOCKED_ATTACKER", ip, f"BANNED_{duration}s")

        block_engine.block_ip(ip, duration)

        print(f"🔥 BLOCKED {ip} for {duration} seconds")

    elif decision == "SUSPICIOUS":

        telemetry.log("SUSPICIOUS_ACTIVITY", ip, "MONITOR")

        print(f"⚠️ Suspicious behavior from {ip}")


# =============================
# EVENT REGISTRATION
# =============================

def register_event(ip, event_name, weight):

    trust_engine.decrease(ip, 10)

    sequence_engine.record_event(ip, event_name)

    seq = sequence_engine.detect_sequence(ip)

    if seq:

        print(f"[SEQUENCE DETECTED] {' → '.join(seq)}")

        risk_engine.add_event(ip, "ATTACK_SEQUENCE", 80)

    risk_engine.add_event(ip, event_name, weight)

    respond_to_threat(ip)


# =============================
# DETECTION PIPELINE
# =============================

def detection_engine(event):

    ip = event.source_ip
    packet = event.raw_packet

    # -------------------------
    # traffic monitor
    # -------------------------

    traffic_monitor.record_packet()

    # -------------------------
    # protocol analysis
    # -------------------------

    proto = protocol_analyzer.analyze(packet)

    print(f"[PROTO] {ip} → {proto['protocol']}:{proto['port']}")

    # -------------------------
    # baseline behavior
    # -------------------------

    baseline_state = baseline_engine.update(ip)

    if baseline_state == "ANOMALOUS":

        print(f"[BASELINE] abnormal traffic from {ip}")

        register_event(ip, "BASELINE_ANOMALY", 30)

    elif baseline_state == "ELEVATED":

        register_event(ip, "BASELINE_ELEVATED", 10)

    # -------------------------
    # known attacker check
    # -------------------------

    if threat_memory.is_known_attacker(ip):

        print(f"⚠️ Known attacker detected: {ip}")

        telemetry.log("KNOWN_ATTACKER", ip, "AUTO_BLOCK")

        block_engine.block_ip(ip, 600)

        return

    # -------------------------
    # TCP stealth scan
    # -------------------------

    anomaly = tcp_analyzer.analyze(packet)

    if anomaly:

        telemetry.log(anomaly, ip, "DETECTED")

        threat_memory.record_attack(ip, anomaly)

        register_event(ip, anomaly, 50)

        return

    # -------------------------
    # port scan detection
    # -------------------------

    if scan_detector.analyze(event):

        telemetry.log("PORT_SCAN", ip, "DETECTED")

        threat_memory.record_attack(ip, "PORT_SCAN")

        register_event(ip, "PORT_SCAN", 40)

        return

    # -------------------------
    # payload attack detection
    # -------------------------

    if payload_inspector.inspect(event.payload):

        telemetry.log("PAYLOAD_ATTACK", ip, "DETECTED")

        threat_memory.record_attack(ip, "PAYLOAD_ATTACK")

        register_event(ip, "PAYLOAD_ATTACK", 60)

        return

    # -------------------------
    # ML detection
    # -------------------------

    features = feature_extractor.update(packet)

    if not features:
        return

    result = ml_detector.analyze(features)

    probability = result["attack_probability"]

    if result["is_attack"]:

        print("\n🤖 AI DETECTED ATTACK")

        print("Probability:", probability)

        if "reason" in result:

            print("Reason:")

            for k, v in result["reason"].items():
                print(f"{k} → {v}")

        telemetry.log("ML_ATTACK_DETECTED", ip, probability)

        threat_memory.record_attack(ip, "ML_ATTACK")

        register_event(ip, "ML_ATTACK", int(probability * 100))

        return

    # -------------------------
    # normal traffic
    # -------------------------

    trust_engine.increase(ip, 1)

    print(f"[SAFE] {ip} → {event.destination_ip}")


# =============================
# START PACKET CAPTURE
# =============================

start_sniffer(detection_engine)
