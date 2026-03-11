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
from core.trust_engine import TrustEngine
from core.traffic_monitor import TrafficMonitor
from core.flow_analyzer import FlowAnalyzer
from core.collaborative_intel import CollaborativeIntel
from core.firewall_control import FirewallControl
from core.control_api import ControlAPI

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

ml_detector = MLDetector()
flow_analyzer = FlowAnalyzer()

protocol_analyzer = ProtocolAnalyzer()

block_engine = BlockEngine()
threat_db = ThreatDB()
threat_memory = ThreatMemory()

telemetry = Telemetry()

risk_engine = RiskEngine()
baseline_engine = BaselineEngine()
sequence_engine = AttackSequenceEngine()

trust_engine = TrustEngine()
traffic_monitor = TrafficMonitor()

collaborative_intel = CollaborativeIntel()
firewall_control = FirewallControl()


# =============================
# STARTUP MODE DISPLAY
# =============================

print(f"🧭 Firewall mode: {firewall_control.get_mode().upper()}")

if firewall_control.is_protection_enabled():
    print("🟢 PROTECT mode active → blocking enabled")
else:
    print("🟡 DETECT mode active → detection only, no blocking")


# =============================
# OPTIONAL RUNTIME RESET HELPER
# =============================

def reset_runtime_state():
    """
    Reset in-memory runtime state safely.
    """
    print("🧹 Resetting runtime in-memory state...")

    try:
        threat_db.threat_map.clear()
    except Exception:
        pass

    try:
        if hasattr(scan_detector, "connection_tracker"):
            scan_detector.connection_tracker.clear()
    except Exception:
        pass

    try:
        if hasattr(flow_analyzer, "flows"):
            flow_analyzer.flows.clear()
    except Exception:
        pass

    try:
        if hasattr(block_engine, "unblock_all"):
            block_engine.unblock_all()
    except Exception:
        pass

    try:
        if hasattr(risk_engine, "risk_map"):
            risk_engine.risk_map.clear()
    except Exception:
        pass

    try:
        if hasattr(sequence_engine, "history"):
            sequence_engine.history.clear()
    except Exception:
        pass

    try:
        if hasattr(traffic_monitor, "ip_activity"):
            traffic_monitor.ip_activity.clear()
    except Exception:
        pass

    print("✅ Runtime state reset complete")


# =============================
# START CONTROL API
# =============================

control_api = ControlAPI(
    firewall_control=firewall_control,
    block_engine=block_engine,
    threat_db=threat_db,
    threat_memory=threat_memory,
    reset_runtime_callback=reset_runtime_state
)

control_api.start(port=7400)


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
# COLLABORATIVE THREAT FEED LOOP
# =============================

def collaborative_feed_loop():
    while True:
        try:
            collaborative_intel.refresh_feed()
        except Exception as e:
            print("Collaborative intel refresh error:", e)

        time.sleep(120)


threading.Thread(
    target=collaborative_feed_loop,
    daemon=True
).start()


# =============================
# RESPONSE ENGINE
# =============================

def respond_to_threat(ip):
    """
    Decide whether to block or monitor based on risk engine.
    Trusted infrastructure must never be blocked.
    """
    if trust_engine.is_trusted(ip):
        print(f"🟢 Trusted IP exempt from response action: {ip}")
        return

    decision = risk_engine.decision(ip)

    if decision == "BLOCK":
        duration = threat_db.get_ban_duration(ip)

        if firewall_control.is_protection_enabled():
            telemetry.log("BLOCKED_ATTACKER", ip, f"BANNED_{duration}s")

            blocked = block_engine.block_ip(ip, duration)

            if blocked:
                print(f"🔥 BLOCKED {ip} for {duration} seconds")
            else:
                print(f"⚠️ Block skipped or failed for {ip}")

        else:
            telemetry.log("WOULD_BLOCK_ATTACKER", ip, f"WOULD_BAN_{duration}s")
            print(f"🟡 DETECT MODE: would block {ip} for {duration} seconds")

    elif decision == "SUSPICIOUS":
        telemetry.log("SUSPICIOUS_ACTIVITY", ip, "MONITOR")
        print(f"⚠️ Suspicious behavior from {ip}")


# =============================
# RECORD EVENTS
# =============================

def register_event(ip, event_name, weight):
    """
    Record suspicious/attack event into all risk layers.
    Trusted infrastructure should never be escalated.
    """
    if trust_engine.is_trusted(ip):
        print(f"🟢 Trusted IP ignored for escalation: {ip} ({event_name})")
        return

    sequence_engine.record_event(ip, event_name)

    seq = sequence_engine.detect_sequence(ip)

    if seq:
        print(f"[SEQUENCE DETECTED] {' → '.join(seq)}")
        risk_engine.add_event(ip, "ATTACK_SEQUENCE", 80)

    risk_engine.add_event(ip, event_name, weight)

    # Reflect in threat DB for block duration logic
    threat_db.add_score(ip, weight)

    # Trust score penalty
    try:
        trust_engine.record_attack(ip)
    except Exception as e:
        print("Trust engine attack scoring error:", e)

    respond_to_threat(ip)


# =============================
# DETECTION PIPELINE
# =============================

def detection_engine(event):
    ip = event.source_ip
    packet = event.raw_packet

    # -------------------------
    # Basic traffic monitor
    # -------------------------
    try:
        traffic_monitor.observe(ip)
    except Exception as e:
        print("Traffic monitor error:", e)

    # -------------------------
    # Trust engine lightweight observe
    # -------------------------
    try:
        trust_engine.observe(ip)
    except Exception as e:
        print("Trust engine error:", e)

    # -------------------------
    # Trusted infra fast path
    # -------------------------
    if trust_engine.is_trusted(ip):
        try:
            trust_engine.record_benign(ip)
        except Exception:
            pass

        print(f"[TRUSTED] {ip} → {event.destination_ip}")
        return

    # -------------------------
    # Collaborative threat intel
    # -------------------------
    try:
        if collaborative_intel.is_known_bad(ip):
            print(f"🌐 Collaborative intel flagged known bad IP: {ip}")

            telemetry.log("COLLAB_INTEL_MATCH", ip, "SHARED_THREAT")
            threat_memory.record_attack(ip, "COLLAB_INTEL_MATCH")

            register_event(ip, "COLLAB_INTEL_MATCH", 70)
            return

    except Exception as e:
        print("Collaborative intel error:", e)

    # -------------------------
    # Protocol analysis
    # -------------------------
    try:
        proto = protocol_analyzer.analyze(packet)
        print(f"[PROTO] {ip} → {proto['protocol']}:{proto['port']}")
    except Exception as e:
        print("Protocol analyzer error:", e)

    # -------------------------
    # Baseline analysis
    # -------------------------
    try:
        baseline_state = baseline_engine.update(ip)

        if baseline_state == "ANOMALOUS":
            print(f"[BASELINE] abnormal traffic from {ip}")
            register_event(ip, "BASELINE_ANOMALY", 30)

    except Exception as e:
        print("Baseline engine error:", e)

    # -------------------------
    # Known attacker memory
    # -------------------------
    if threat_memory.is_known_attacker(ip):
        print(f"⚠️ Known attacker detected: {ip}")

        if firewall_control.is_protection_enabled():
            telemetry.log("KNOWN_ATTACKER", ip, "AUTO_BLOCK")

            blocked = block_engine.block_ip(ip, 600)
            if blocked:
                print(f"🔥 AUTO-BLOCKED known attacker {ip} for 600 seconds")
            else:
                print(f"⚠️ Auto-block skipped or failed for {ip}")

        else:
            telemetry.log("KNOWN_ATTACKER", ip, "WOULD_AUTO_BLOCK")
            print(f"🟡 DETECT MODE: would auto-block known attacker {ip}")

        return

    # -------------------------
    # TCP stealth scan
    # -------------------------
    anomaly = tcp_analyzer.analyze(packet)

    if anomaly:
        telemetry.log(anomaly, ip, "DETECTED")
        threat_memory.record_attack(ip, anomaly)

        try:
            collaborative_intel.report_threat(ip, anomaly)
        except Exception as e:
            print("Threat share error:", e)

        register_event(ip, anomaly, 50)
        return

    # -------------------------
    # Port scan
    # -------------------------
    if scan_detector.analyze(event):
        telemetry.log("PORT_SCAN", ip, "DETECTED")
        threat_memory.record_attack(ip, "PORT_SCAN")

        try:
            collaborative_intel.report_threat(ip, "PORT_SCAN")
        except Exception as e:
            print("Threat share error:", e)

        register_event(ip, "PORT_SCAN", 40)
        return

    # -------------------------
    # Payload attack
    # -------------------------
    if payload_inspector.inspect(event.payload):
        telemetry.log("PAYLOAD_ATTACK", ip, "DETECTED")
        threat_memory.record_attack(ip, "PAYLOAD_ATTACK")

        try:
            collaborative_intel.report_threat(ip, "PAYLOAD_ATTACK")
        except Exception as e:
            print("Threat share error:", e)

        register_event(ip, "PAYLOAD_ATTACK", 60)
        return

    # -------------------------
    # ML detection (51-feature aligned)
    # -------------------------
    features = flow_analyzer.update(packet)

    if not features:
        return

    print(f"[ML] Feature vector generated: {len(features)} features")

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

        try:
            collaborative_intel.report_threat(ip, "ML_ATTACK")
        except Exception as e:
            print("Threat share error:", e)

        register_event(ip, "ML_ATTACK", int(probability * 100))
        return

    # -------------------------
    # Safe traffic
    # -------------------------
    try:
        trust_engine.record_benign(ip)
    except Exception:
        pass

    print(f"[SAFE] {ip} → {event.destination_ip}")


# =============================
# START PACKET CAPTURE
# =============================

start_sniffer(detection_engine)
