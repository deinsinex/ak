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
import ipaddress


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

# Event dedup / cooldown memory
event_cooldowns = {}

# Per-IP last-seen timestamps for very light traffic heuristics
ip_last_seen = {}

# Cooldown windows (seconds)
EVENT_COOLDOWN_SECONDS = {
    "BASELINE_ANOMALY": 180,       # calmer than before
    "COLLAB_THREAT_FEED": 600,     # much calmer
    "PORT_SCAN": 90,
    "PAYLOAD_ATTACK": 60,
    "ML_ATTACK": 180,              # calmer
    "ATTACK_SEQUENCE": 180,
    "SYN_SCAN": 90,
    "XMAS_SCAN": 90,
    "NULL_SCAN": 90,
    "KNOWN_ATTACKER": 300,
}


# =========================================================
# SAFE / SHARE FILTER HELPERS
# =========================================================

def is_private_or_local_ip(ip):
    """
    True for private, loopback, link-local, reserved, multicast, unspecified.
    These should never be shared into collaborative threat intel
    and should not be treated as remote malicious reputation.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private or
            addr.is_loopback or
            addr.is_link_local or
            addr.is_multicast or
            addr.is_reserved or
            addr.is_unspecified
        )
    except Exception:
        return True


def is_safe_common_service_port(port):
    """
    Common client/server ports that frequently appear in normal browsing / updates.
    """
    return port in {53, 80, 443, 123}


def is_likely_benign_service(ip, port):
    """
    Conservative false-positive reducer:
    If traffic is going to common web/DNS/NTP ports, do NOT treat collaborative
    intel alone as enough to escalate hard.
    """
    if is_private_or_local_ip(ip):
        return True

    if allowlist_engine and allowlist_engine.is_allowlisted(ip):
        return True

    if is_safe_common_service_port(port):
        return True

    return False


def should_share_event(ip, event_name, weight):
    """
    Only share high-confidence remote attacker events.
    Prevent poisoning / self-feedback loops.
    """
    if is_private_or_local_ip(ip):
        return False

    if allowlist_engine and allowlist_engine.is_allowlisted(ip):
        return False

    if event_name == "COLLAB_THREAT_FEED":
        return False

    # Only share stronger signals
    if weight < 40:
        return False

    # Do not share weak baseline-only anomalies
    if event_name == "BASELINE_ANOMALY":
        return False

    return True


def should_process_event(ip, event_name):
    """
    Per-IP per-event cooldown to prevent score inflation and noisy repeated detections.
    """
    now = time.time()
    key = f"{ip}:{event_name}"
    cooldown = EVENT_COOLDOWN_SECONDS.get(event_name, 60)

    last_seen = event_cooldowns.get(key)
    if last_seen is not None and (now - last_seen) < cooldown:
        return False

    event_cooldowns[key] = now
    return True


def cleanup_event_cooldowns():
    """
    Periodically remove stale cooldown entries.
    """
    now = time.time()
    stale_keys = []

    for key, ts in list(event_cooldowns.items()):
        if (now - ts) > 1800:  # 30 min cleanup horizon
            stale_keys.append(key)

    for key in stale_keys:
        event_cooldowns.pop(key, None)


def cleanup_ip_last_seen():
    """
    Prevent unbounded growth of simple timing memory.
    """
    now = time.time()
    stale_ips = []

    for ip, ts in list(ip_last_seen.items()):
        if (now - ts) > 1800:
            stale_ips.append(ip)

    for ip in stale_ips:
        ip_last_seen.pop(ip, None)


def is_rapid_repeat(ip, threshold_seconds=1.0):
    """
    Very light heuristic:
    returns True if this IP is appearing repeatedly very quickly.
    Useful to avoid flagging one-off normal connections as baseline anomalies.
    """
    now = time.time()
    last = ip_last_seen.get(ip)
    ip_last_seen[ip] = now

    if last is None:
        return False

    return (now - last) <= threshold_seconds


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
    global event_cooldowns
    global ip_last_seen

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

    event_cooldowns = {}
    ip_last_seen = {}

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

    try:
        shared_threats = collaborative_intel.count() if collaborative_intel else 0
    except Exception:
        shared_threats = 0

    try:
        traffic_stats = traffic_monitor.stats() if traffic_monitor else {}
    except Exception:
        traffic_stats = {}

    return {
        "status": "ok",
        "mode": mode,
        "protection_enabled": firewall_control.is_protection_enabled() if firewall_control else False,
        "active_block_count": len(active_blocks),
        "active_blocks": active_blocks,
        "allowlist": allowlist,
        "shared_threat_count": shared_threats,
        "traffic": traffic_stats
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
    Clears persistent files + recreates runtime engine objects.
    Also removes current iptables blocks.
    """
    global block_engine

    print("\n🧹 FULL FIREWALL RESET STARTED")

    try:
        if block_engine is not None:
            block_engine.unblock_all()
    except Exception as e:
        print(f"[RESET] Failed to unblock all before reset: {e}")

    try:
        if firewall_control is not None:
            firewall_control.reset_memory_files()
    except Exception as e:
        print(f"[RESET] Failed to clear persistent files: {e}")

    initialize_engines()

    try:
        register_control_runtime()
    except Exception as e:
        print(f"[RESET] Failed to re-register control API runtime: {e}")

    print("✅ FULL FIREWALL RESET COMPLETE")


# =========================================================
# BACKGROUND LOOPS
# =========================================================

def model_update_loop():
    while True:
        print("Checking for global model update...")

        try:
            fetch_global_model()
        except Exception as e:
            print("Federated update error:", e)

        time.sleep(300)


def collaborative_intel_loop():
    while True:
        try:
            collaborative_intel.refresh()
        except Exception as e:
            print(f"[COLLAB INTEL] Update error: {e}")

        time.sleep(60)


def cooldown_cleanup_loop():
    while True:
        try:
            cleanup_event_cooldowns()
            cleanup_ip_last_seen()
        except Exception as e:
            print(f"[COOLDOWN] Cleanup error: {e}")

        time.sleep(120)


# =========================================================
# RESPONSE ENGINE
# =========================================================

def respond_to_threat(ip):
    decision = risk_engine.decision(ip)

    if decision == "BLOCK":

        if not firewall_control.is_protection_enabled():
            telemetry.log("BLOCK_SKIPPED_DETECT_MODE", ip, "DETECT_ONLY")
            print(f"🟡 DETECT MODE: would block {ip}, but protection is disabled")
            return

        if allowlist_engine.is_allowlisted(ip):
            telemetry.log("ALLOWLISTED_BLOCK_SKIPPED", ip, "ALLOWLISTED")
            print(f"🟢 Allowlisted IP not blocked: {ip}")
            return

        if is_private_or_local_ip(ip):
            telemetry.log("LOCAL_IP_BLOCK_SKIPPED", ip, "LOCAL_INFRA")
            print(f"🔵 Local/private IP not blocked: {ip}")
            return

        duration = threat_db.get_ban_duration(ip)

        telemetry.log("BLOCKED_ATTACKER", ip, f"BANNED_{duration}s")

        applied = block_engine.block_ip(ip, duration)

        if applied:
            print(f"🔥 BLOCKED {ip} for {duration} seconds")
        else:
            print(f"⚠️ Block attempt failed or already active for {ip}")

    elif decision == "SUSPICIOUS":
        telemetry.log("SUSPICIOUS_ACTIVITY", ip, "MONITOR")
        print(f"⚠️ Suspicious behavior from {ip}")


# =========================================================
# EVENT REGISTRATION
# =========================================================

def register_event(ip, event_name, weight):
    if not should_process_event(ip, event_name):
        print(f"[COOLDOWN] Skipping repeated {event_name} for {ip}")
        return

    try:
        traffic_monitor.record_attack()
    except Exception as e:
        print(f"[TRAFFIC MONITOR] Failed to record attack: {e}")

    if weight >= 60:
        trust_engine.record_attack(ip)
    else:
        trust_engine.record_suspicious(ip)

    sequence_engine.record_event(ip, event_name)

    seq = sequence_engine.detect_sequence(ip)
    if seq:
        if should_process_event(ip, "ATTACK_SEQUENCE"):
            print(f"[SEQUENCE DETECTED] {' → '.join(seq)}")
            risk_engine.add_event(ip, "ATTACK_SEQUENCE", 80)

    try:
        threat_intel_engine.record_event(ip, event_name)
    except Exception as e:
        print(f"[THREAT INTEL] Local record failed: {e}")

    try:
        if should_share_event(ip, event_name, weight):
            share_threat_event(ip, event_name)
        else:
            print(f"[THREAT SHARE] Skipped sharing {event_name} for {ip}")
    except Exception as e:
        print(f"[THREAT SHARE] Failed to share event: {e}")

    risk_engine.add_event(ip, event_name, weight)
    respond_to_threat(ip)


# =========================================================
# DETECTION PIPELINE
# =========================================================

def detection_engine(event):
    ip = event.source_ip
    packet = event.raw_packet

    if allowlist_engine.is_allowlisted(ip):
        return

    proto = protocol_analyzer.analyze(packet)
    dst_port = proto.get("port")
    print(f"[PROTO] {ip} → {proto['protocol']}:{dst_port}")

    try:
        traffic_monitor.record_packet(ip)
    except Exception as e:
        print(f"[TRAFFIC MONITOR] Failed to record packet: {e}")

    # Keep local/private visible, but do not score/enforce
    if is_private_or_local_ip(ip):
        return

    # -----------------------------------------------------
    # BASELINE (calmer)
    # Only score baseline anomaly if it repeats quickly AND
    # it is not just routine web/DNS/NTP traffic
    # -----------------------------------------------------
    baseline_state = baseline_engine.update(ip)

    if baseline_state == "ANOMALOUS":
        if is_rapid_repeat(ip, threshold_seconds=1.0) and not is_safe_common_service_port(dst_port):
            print(f"[BASELINE] abnormal traffic from {ip}")
            register_event(ip, "BASELINE_ANOMALY", 15)
        else:
            # Visible for debugging, but no risk inflation
            print(f"[BASELINE] benign-ish anomaly ignored for {ip}")

    # -----------------------------------------------------
    # KNOWN ATTACKER
    # -----------------------------------------------------
    if threat_memory.is_known_attacker(ip):
        if should_process_event(ip, "KNOWN_ATTACKER"):
            print(f"⚠️ Known attacker detected: {ip}")
            telemetry.log("KNOWN_ATTACKER", ip, "AUTO_BLOCK")

            if firewall_control.is_protection_enabled() and not allowlist_engine.is_allowlisted(ip):
                block_engine.block_ip(ip, 600)
            else:
                print(f"🟡 DETECT MODE or allowlisted: known attacker not blocked ({ip})")
        return

    # -----------------------------------------------------
    # COLLABORATIVE INTEL (much safer)
    # Do NOT aggressively escalate for common web service ports
    # -----------------------------------------------------
    try:
        rep = collaborative_intel.get_shared_score(ip)

        if rep >= 50:
            reason = collaborative_intel.get_shared_reason(ip) or "SHARED_THREAT"

            if is_likely_benign_service(ip, dst_port):
                print(f"[COLLAB INTEL] Reputation noted but softened for {ip}: {rep} ({reason})")
            else:
                print(f"[COLLAB INTEL] Known bad reputation for {ip}: {rep} ({reason})")
                register_event(ip, "COLLAB_THREAT_FEED", 35)
                return

    except Exception as e:
        print(f"[COLLAB INTEL] Reputation lookup failed: {e}")

    # -----------------------------------------------------
    # TCP FLAG / SIGNATURE SCANS
    # -----------------------------------------------------
    anomaly = tcp_analyzer.analyze(packet)

    if anomaly:
        telemetry.log(anomaly, ip, "DETECTED")
        threat_memory.record_attack(ip, anomaly)
        register_event(ip, anomaly, 50)
        return

    # -----------------------------------------------------
    # PORT SCAN DETECTOR
    # Existing detector kept, but don't overreact to common ports
    # -----------------------------------------------------
    if scan_detector.analyze(event):
        if is_safe_common_service_port(dst_port):
            print(f"[SCAN] Common service-port scan-like pattern softened for {ip}")
        else:
            telemetry.log("PORT_SCAN", ip, "DETECTED")
            threat_memory.record_attack(ip, "PORT_SCAN")
            register_event(ip, "PORT_SCAN", 40)
            return

    # -----------------------------------------------------
    # PAYLOAD ATTACK
    # -----------------------------------------------------
    if payload_inspector.inspect(event.payload):
        telemetry.log("PAYLOAD_ATTACK", ip, "DETECTED")
        threat_memory.record_attack(ip, "PAYLOAD_ATTACK")
        register_event(ip, "PAYLOAD_ATTACK", 60)
        return

    # -----------------------------------------------------
    # FLOW FEATURES + ML
    # -----------------------------------------------------
    features = flow_analyzer.update(packet)

    if not features:
        trust_engine.record_benign(ip)
        return

    result = ml_detector.analyze(features)
    probability = result["attack_probability"]

    # Make ML less aggressive:
    # require both model attack AND high confidence
    if result["is_attack"] and probability >= 0.92:
        if should_process_event(ip, "ML_ATTACK"):
            print("\n🤖 AI DETECTED ATTACK")
            print("Probability:", probability)

            telemetry.log("ML_ATTACK_DETECTED", ip, probability)
            threat_memory.record_attack(ip, "ML_ATTACK")
            register_event(ip, "ML_ATTACK", 35)
        else:
            print(f"[COOLDOWN] Skipping repeated ML_ATTACK for {ip}")
        return

    trust_engine.record_benign(ip)
    print(f"[SAFE] {ip} → {event.destination_ip}")


# =========================================================
# MAIN STARTUP
# =========================================================

if __name__ == "__main__":
    print("\n🛡️ Aegis AI Firewall Starting...\n")

    threading.Thread(target=start_attack_dashboard, daemon=True).start()
    threading.Thread(target=start_control_api, daemon=True).start()

    initialize_engines()
    register_control_runtime()

    threading.Thread(target=model_update_loop, daemon=True).start()
    threading.Thread(target=collaborative_intel_loop, daemon=True).start()
    threading.Thread(target=cooldown_cleanup_loop, daemon=True).start()

    print(f"🟡 Firewall mode: {firewall_control.get_mode().upper()}")
    print(f"🟢 Allowlist summary: {allowlist_engine.summary()}")
    print(f"🧠 Shared threat count: {collaborative_intel.count()}")

    start_sniffer(detection_engine)
