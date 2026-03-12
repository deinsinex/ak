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
from core.firewall_control import FirewallControl
from core.flow_analyzer import FlowAnalyzer
from core.threat_intel_engine import ThreatIntelEngine
from core.collaborative_intel import CollaborativeIntel
from core.allowlist_engine import AllowlistEngine

from ml.ml_detector import MLDetector

from federation.update_client import fetch_global_model
from federation.threat_share import share_threat_event

from visualization.dashboard_server import start_attack_dashboard
from visualization.control_api import start_control_api, register_runtime

import threading
import time


print("\n🛡️ Aegis AI Firewall Starting...\n")


# =========================================================
# GLOBAL ENGINES (RUNTIME OBJECTS)
# =========================================================

payload_inspector = None
scan_detector = None
tcp_analyzer = None
protocol_analyzer = None
ml_detector = None

block_engine = None
threat_db = None
threat_memory = None
telemetry = None
risk_engine = None
baseline_engine = None
sequence_engine = None
traffic_monitor = None
trust_engine = None
firewall_control = None
flow_analyzer = None
threat_intel_engine = None
collaborative_intel = None
allowlist_engine = None


# =========================================================
# INITIALIZE / RESET RUNTIME ENGINES
# =========================================================

def initialize_engines():
    global payload_inspector
    global scan_detector
    global tcp_analyzer
    global protocol_analyzer
    global ml_detector

    global block_engine
    global threat_db
    global threat_memory
    global telemetry
    global risk_engine
    global baseline_engine
    global sequence_engine
    global traffic_monitor
    global trust_engine
    global firewall_control
    global flow_analyzer
    global threat_intel_engine
    global collaborative_intel
    global allowlist_engine

    payload_inspector = PayloadInspector()
    scan_detector = ScanDetector()
    tcp_analyzer = TCPFlagAnalyzer()
    protocol_analyzer = ProtocolAnalyzer()
    ml_detector = MLDetector()

    block_engine = BlockEngine()
    threat_db = ThreatDB()
    threat_memory = ThreatMemory()
    telemetry = Telemetry()
    risk_engine = RiskEngine()
    baseline_engine = BaselineEngine()
    sequence_engine = AttackSequenceEngine()
    traffic_monitor = TrafficMonitor()
    trust_engine = TrustEngine()
    firewall_control = FirewallControl()
    flow_analyzer = FlowAnalyzer()
    threat_intel_engine = ThreatIntelEngine()
    collaborative_intel = CollaborativeIntel()
    allowlist_engine = AllowlistEngine()

    print("✅ All Aegis engines initialized")


# =========================================================
# STATUS CALLBACK FOR CONTROL API
# =========================================================

def get_runtime_status():
    try:
        mode = firewall_control.get_mode() if firewall_control else "unknown"
    except Exception:
        mode = "unknown"

    try:
        active_blocks = list(block_engine.active_blocks.keys()) if block_engine else []
    except Exception:
        active_blocks = []

    try:
        allowlist = allowlist_engine.summary() if allowlist_engine else {}
    except Exception:
        allowlist = {}

    return {
        "status": "ok",
        "mode": mode,
        "protection_enabled": firewall_control.is_protection_enabled() if firewall_control else False,
        "active_block_count": len(active_blocks),
        "active_blocks": active_blocks,
        "allowlist": allowlist
    }


# =========================================================
# CONTROL API REGISTRATION
# =========================================================

def register_control_runtime():
    register_runtime(
        firewall_control=firewall_control,
        block_engine=block_engine,
        allowlist_engine=allowlist_engine,
        reset_callback=reset_firewall_runtime,
        status_callback=get_runtime_status
    )


# =========================================================
# RESET RUNTIME + FILE STATE
# =========================================================

def reset_firewall_runtime():
    """
    Clears persistent files + removes current Aegis blocks +
    recreates runtime engine objects + re-registers control API.
    """
    global block_engine

    print("\n🧹 FULL FIREWALL RESET STARTED")

    # Remove active firewall blocks first
    try:
        if block_engine is not None:
            block_engine.unblock_all()
    except Exception as e:
        print(f"[RESET] Failed to unblock all before reset: {e}")

    # Clear persistent files
    try:
        if firewall_control is not None:
            firewall_control.reset_memory_files()
    except Exception as e:
        print(f"[RESET] Failed to clear persistent files: {e}")

    # Recreate all runtime objects (this resets trust/risk/sequence/etc in memory)
    initialize_engines()

    # Re-register updated runtime objects into control API
    try:
        register_control_runtime()
    except Exception as e:
        print(f"[RESET] Failed to re-register control API runtime: {e}")

    print("✅ FULL FIREWALL RESET COMPLETE")


# =========================================================
# START DASHBOARD + CONTROL API
# =========================================================

threading.Thread(
    target=start_attack_dashboard,
    daemon=True
).start()

threading.Thread(
    target=start_control_api,
    daemon=True
).start()


# =========================================================
# FEDERATED MODEL UPDATER (PULL ONLY)
# =========================================================

def model_update_loop():
    while True:
        print("Checking for global model update...")

        try:
            fetch_global_model()
        except Exception as e:
            print("Federated update error:", e)

        time.sleep(300)


# =========================================================
# COLLABORATIVE THREAT FEED LOOP
# =========================================================

def collaborative_intel_loop():
    while True:
        try:
            collaborative_intel.refresh()
        except Exception as e:
            print(f"[COLLAB INTEL] Update error: {e}")

        time.sleep(60)


# =========================================================
# RESPONSE ENGINE (SINGLE ENFORCEMENT PATH)
# =========================================================

def respond_to_threat(ip):
    decision = risk_engine.decision(ip)

    if decision == "BLOCK":

        # Detect-only mode: log but do not enforce
        if not firewall_control.is_protection_enabled():
            telemetry.log("BLOCK_SKIPPED_DETECT_MODE", ip, "DETECT_ONLY")
            print(f"🟡 DETECT MODE: would block {ip}, but protection is disabled")
            return

        # Never block allowlisted IPs
        if allowlist_engine.is_allowlisted(ip):
            telemetry.log("ALLOWLISTED_BLOCK_SKIPPED", ip, "ALLOWLISTED")
            print(f"🟢 Allowlisted IP not blocked: {ip}")
            return

        duration = threat_db.get_ban_duration(ip)

        telemetry.log("BLOCKED_ATTACKER", ip, f"BANNED_{duration}s")

        success = block_engine.block_ip(ip, duration)

        if success:
            print(f"🔥 BLOCKED {ip} for {duration} seconds")
        else:
            print(f"⚠️ Block attempted but not confirmed for {ip}")

    elif decision == "SUSPICIOUS":
        telemetry.log("SUSPICIOUS_ACTIVITY", ip, "MONITOR")
        print(f"⚠️ Suspicious behavior from {ip}")


# =========================================================
# EVENT REGISTRATION
# =========================================================

def register_event(ip, event_name, weight):
    # Trust degradation
    if weight >= 60:
        trust_engine.record_attack(ip)
    else:
        trust_engine.record_suspicious(ip)

    # Sequence memory
    sequence_engine.record_event(ip, event_name)

    seq = sequence_engine.detect_sequence(ip)

    if seq:
        print(f"[SEQUENCE DETECTED] {' → '.join(seq)}")
        risk_engine.add_event(ip, "ATTACK_SEQUENCE", 80)

    # Threat intelligence (local)
    try:
        threat_intel_engine.record_event(ip, event_name)
    except Exception as e:
        print(f"[THREAT INTEL] Local record failed: {e}")

    # Threat intelligence (shared)
    try:
        share_threat_event(ip, event_name)
    except Exception as e:
        print(f"[THREAT SHARE] Failed to share event: {e}")

    # Risk engine
    risk_engine.add_event(ip, event_name, weight)

    # Final response
    respond_to_threat(ip)


# =========================================================
# DETECTION PIPELINE
# =========================================================

def detection_engine(event):
    ip = event.source_ip
    packet = event.raw_packet

    # -----------------------------------------------------
    # Allowlist bypass (safe + visible in telemetry)
    # -----------------------------------------------------
    if allowlist_engine.is_allowlisted(ip):
        telemetry.log("ALLOWLIST_BYPASS", ip, "ALLOWLISTED")
        return

    # -----------------------------------------------------
    # Protocol analysis
    # -----------------------------------------------------
    proto = protocol_analyzer.analyze(packet)
    print(f"[PROTO] {ip} → {proto['protocol']}:{proto['port']}")

    # -----------------------------------------------------
    # Traffic monitor
    # -----------------------------------------------------
    traffic_monitor.observe(ip)

    # -----------------------------------------------------
    # Baseline analysis
    # -----------------------------------------------------
    baseline_state = baseline_engine.update(ip)

    if baseline_state == "ANOMALOUS":
        print(f"[BASELINE] abnormal traffic from {ip}")
        register_event(ip, "BASELINE_ANOMALY", 30)

    # -----------------------------------------------------
    # Known attacker (must go through unified response path)
    # -----------------------------------------------------
    if threat_memory.is_known_attacker(ip):
        print(f"⚠️ Known attacker detected: {ip}")

        telemetry.log("KNOWN_ATTACKER", ip, "HIGH_RISK")

        # Use unified policy path instead of direct block
        risk_engine.add_event(ip, "KNOWN_ATTACKER", 90)
        respond_to_threat(ip)
        return

    # -----------------------------------------------------
    # Collaborative intel reputation
    # -----------------------------------------------------
    try:
        rep = collaborative_intel.get_shared_score(ip)

        if rep >= 50:
            print(f"[COLLAB INTEL] Known bad reputation for {ip}: {rep}")
            register_event(ip, "COLLAB_THREAT_FEED", 70)
            return

    except Exception as e:
        print(f"[COLLAB INTEL] Reputation lookup failed: {e}")

    # -----------------------------------------------------
    # TCP stealth scan
    # -----------------------------------------------------
    anomaly = tcp_analyzer.analyze(packet)

    if anomaly:
        telemetry.log(anomaly, ip, "DETECTED")
        threat_memory.record_attack(ip, anomaly)
        register_event(ip, anomaly, 50)
        return

    # -----------------------------------------------------
    # Port scan
    # -----------------------------------------------------
    if scan_detector.analyze(event):
        telemetry.log("PORT_SCAN", ip, "DETECTED")
        threat_memory.record_attack(ip, "PORT_SCAN")
        register_event(ip, "PORT_SCAN", 40)
        return

    # -----------------------------------------------------
    # Payload attack
    # -----------------------------------------------------
    if payload_inspector.inspect(event.payload):
        telemetry.log("PAYLOAD_ATTACK", ip, "DETECTED")
        threat_memory.record_attack(ip, "PAYLOAD_ATTACK")
        register_event(ip, "PAYLOAD_ATTACK", 60)
        return

    # -----------------------------------------------------
    # Flow analysis → ML features
    # -----------------------------------------------------
    features = flow_analyzer.update(packet)

    if not features:
        trust_engine.record_benign(ip)
        return

    # -----------------------------------------------------
    # ML detection
    # -----------------------------------------------------
    result = ml_detector.analyze(features)
    probability = result["attack_probability"]

    if result["is_attack"]:
        print("\n🤖 AI DETECTED ATTACK")
        print("Probability:", probability)

        telemetry.log("ML_ATTACK_DETECTED", ip, probability)

        threat_memory.record_attack(ip, "ML_ATTACK")

        register_event(ip, "ML_ATTACK", int(probability * 100))
        return

    # -----------------------------------------------------
    # Benign outcome
    # -----------------------------------------------------
    trust_engine.record_benign(ip)
    print(f"[SAFE] {ip} → {event.destination_ip}")


# =========================================================
# MAIN STARTUP
# =========================================================

if __name__ == "__main__":
    initialize_engines()

    # Register control API runtime after objects exist
    register_control_runtime()

    threading.Thread(
        target=model_update_loop,
        daemon=True
    ).start()

    threading.Thread(
        target=collaborative_intel_loop,
        daemon=True
    ).start()

    # NOTE:
    # Real federated training is currently run manually via:
    #   python -m federated.run_federated
    # We intentionally do NOT auto-push background weights from main.py
    # until a true online local trainer is implemented.

    print(f"🟡 Firewall mode: {firewall_control.get_mode().upper()}")
    print(f"🟢 Allowlist summary: {allowlist_engine.summary()}")

    # Start packet capture
    start_sniffer(detection_engine)
