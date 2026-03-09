# Aegis AI Firewall

Aegis AI Firewall is an intelligent network defense system that combines
signature detection, machine learning, and federated learning to detect
and block malicious traffic in real time.

## Features

- Real-time packet inspection using Scapy
- TCP stealth scan detection
- Port scan detection
- Malicious payload inspection
- Machine learning attack detection (XGBoost + SHAP)
- Adaptive IP blocking
- Threat reputation system
- Telemetry logging
- Live attack visualization dashboard
- Federated learning model updates

## Architecture

Packet Capture → Detection Engines → ML Analysis → Threat Scoring → Response Engine → Telemetry & Dashboard

## Technologies Used

- Python
- Scapy
- XGBoost
- SHAP
- Flask
- Federated Learning
- iptables

## Running the Firewall

python main.py


## Dashboard

The live attack map runs on:
http://localhost:7000


## Federated Learning

Edge firewalls collaboratively improve detection models without sharing raw traffic data.

---

Developed by Akshay
