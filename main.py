from capture.scapy_sniffer import start_sniffer

from detect.payload_inspector import PayloadInspector
from detect.scan_detector import ScanDetector
from detect.tcp_flag_analyzer import TCPFlagAnalyzer

from decision.block_engine import BlockEngine
from intel.threat_db import ThreatDB
from intel.threat_memory import ThreatMemory

from core.telemetry import Telemetry

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

block_engine = BlockEngine()
threat_db = ThreatDB()
threat_memory = ThreatMemory()

telemetry = Telemetry()


# =============================
# START DASHBOARD
# =============================

threading.Thread(
    target=start_attack_dashboard,
    name="attack_dashboard",
    daemon=True
).start()


# =============================
# FEDERATED MODEL UPDATER
# =============================

def model_update_loop():

    # wait for firewall to fully start
    time.sleep(10)

    while True:

        try:

            print("Checking for global model update...")

            fetch_global_model()

        except Exception as e:

            print("Federated update error:", e)

        time.sleep(300)


threading.Thread(
    target=model_update_loop,
    name="federated_updater",
    daemon=True
).start()


# =============================
# RESPONSE ENGINE
# =============================

def respond_to_threat(ip, score):

    if threat_db.should_block(ip):

        duration = threat_db.get_ban_duration(ip)

        telemetry.log("BLOCKED_ATTACKER", ip, f"BANNED_{duration}s")

        block_engine.block_ip(ip, duration)

        print(f"🔥 BLOCKED {ip} for {duration} seconds")

        return

    if score >= 60:

        telemetry.log("HIGH_RISK_ACTIVITY", ip, score)

        print(f"⚠️ Suspicious behavior from {ip}")


# =============================
# DETECTION PIPELINE
# =============================

def detection_engine(event):

    try:

        ip = event.source_ip


        # ---------------------
        # Known attacker check
        # ---------------------

        if threat_memory.is_known_attacker(ip):

            print(f"⚠️ Known attacker detected: {ip}")

            telemetry.log("KNOWN_ATTACKER", ip, "AUTO_BLOCK")

            block_engine.block_ip(ip, 600)

            return


        # ---------------------
        # TCP stealth scan detection
        # ---------------------

        anomaly = tcp_analyzer.analyze(event.raw_packet)

        if anomaly:

            telemetry.log(anomaly, ip, "SCORED")

            score = threat_db.add_score(ip, 50)

            threat_memory.record_attack(ip, anomaly)

            respond_to_threat(ip, score)

            return


        # ---------------------
        # Port scan detection
        # ---------------------

        if scan_detector.analyze(event):

            telemetry.log("PORT_SCAN", ip, "SCORED")

            score = threat_db.add_score(ip, 40)

            threat_memory.record_attack(ip, "PORT_SCAN")

            respond_to_threat(ip, score)

            return


        # ---------------------
        # Payload attack detection
        # ---------------------

        if payload_inspector.inspect(event.payload):

            telemetry.log("PAYLOAD_ATTACK", ip, "SCORED")

            score = threat_db.add_score(ip, 60)

            threat_memory.record_attack(ip, "PAYLOAD_ATTACK")

            respond_to_threat(ip, score)

            return


        # ---------------------
        # ML Feature Extraction
        # ---------------------

        features = feature_extractor.update(event.raw_packet)

        if not features:
            return


        # ---------------------
        # ML Detection
        # ---------------------

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

            score = threat_db.add_score(ip, int(probability * 100))

            respond_to_threat(ip, score)

            return


        # Safe traffic (disabled to prevent log spam)
        # print(f"[SAFE] {ip} → {event.destination_ip}")

    except Exception as e:

        print("Detection pipeline error:", e)


# =============================
# START PACKET CAPTURE
# =============================

try:

    start_sniffer(detection_engine)

except KeyboardInterrupt:

    print("\n🛑 Firewall shutting down.")
