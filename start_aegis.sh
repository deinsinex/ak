#!/bin/bash

# ======================================
# AEGIS AI FIREWALL SOC LAB LAUNCHER
# ======================================

PROJECT_ROOT="/home/akshay/edge_ml"
PYTHON_BIN="/home/akshay/federated_env/bin/python"

FED_SERVER_MODULE="federation.server"
THREAT_INTEL_MODULE="federation.threat_intel_server"

MAIN_APP="$PROJECT_ROOT/main.py"
SOC_GLOBE="$PROJECT_ROOT/visualization/soc_globe.py"
ATTACK_SIM="$PROJECT_ROOT/visualization/attack_simulator.py"
SOC_WALL="$PROJECT_ROOT/visualization/soc_wall.py"
CONTROL_CENTER="$PROJECT_ROOT/visualization/control_center.py"
VULN_SERVER="$PROJECT_ROOT/lab/vulnerable_server.py"

echo ""
echo "======================================"
echo "     AEGIS AI FIREWALL SOC LAB"
echo "======================================"
echo ""

# -----------------------------
# PRECHECKS
# -----------------------------

if ! command -v gnome-terminal >/dev/null 2>&1; then
    echo "❌ gnome-terminal is not installed."
    echo "Install it with:"
    echo "sudo apt update && sudo apt install gnome-terminal -y"
    exit 1
fi

if [ ! -x "$PYTHON_BIN" ]; then
    echo "❌ Python interpreter not found:"
    echo "$PYTHON_BIN"
    exit 1
fi

if [ ! -d "$PROJECT_ROOT" ]; then
    echo "❌ Project root not found:"
    echo "$PROJECT_ROOT"
    exit 1
