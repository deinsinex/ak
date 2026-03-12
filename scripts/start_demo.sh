#!/usr/bin/env bash

set -e

PROJECT_DIR="$HOME/edge_ml"
PYTHON_BIN="$HOME/federated_env/bin/python"

mkdir -p "$PROJECT_DIR/logs/runtime"

echo "🛡️ Starting Aegis AI Firewall Demo Stack..."
echo

# -------------------------------------------------
# Kill old processes first (safe cleanup)
# -------------------------------------------------
pkill -f "python -m federation.server" 2>/dev/null || true
pkill -f "lab/vulnerable_server.py" 2>/dev/null || true
pkill -f "python main.py" 2>/dev/null || true
pkill -f "python -m visualization.attack_simulator" 2>/dev/null || true
pkill -f "python visualization/soc_wall.py" 2>/dev/null || true
pkill -f "python visualization/control_center.py" 2>/dev/null || true

sleep 2

cd "$PROJECT_DIR"

# -------------------------------------------------
# 1) Federated Server
# -------------------------------------------------
nohup "$PYTHON_BIN" -m federation.server > logs/runtime/federation.log 2>&1 &
echo $! > logs/runtime/federation.pid
echo "✅ Federation server started (PID $(cat logs/runtime/federation.pid))"

sleep 2

# -------------------------------------------------
# 2) Vulnerable Server
# -------------------------------------------------
nohup "$PYTHON_BIN" lab/vulnerable_server.py > logs/runtime/vulnerable.log 2>&1 &
echo $! > logs/runtime/vulnerable.pid
echo "✅ Vulnerable server started (PID $(cat logs/runtime/vulnerable.pid))"

sleep 2

# -------------------------------------------------
# 3) Main Firewall (needs sudo)
# -------------------------------------------------
echo "🔐 Starting main firewall (sudo required)..."
sudo -E "$PYTHON_BIN" main.py > logs/runtime/main.log 2>&1 &
echo $! > logs/runtime/main.pid
echo "✅ Main firewall started (PID $(cat logs/runtime/main.pid))"

sleep 5

# -------------------------------------------------
# 4) Attack Simulator
# -------------------------------------------------
nohup "$PYTHON_BIN" -m visualization.attack_simulator > logs/runtime/attack_simulator.log 2>&1 &
echo $! > logs/runtime/attack_simulator.pid
echo "✅ Attack simulator started (PID $(cat logs/runtime/attack_simulator.pid))"

sleep 2

# -------------------------------------------------
# 5) SOC Wall
# -------------------------------------------------
nohup "$PYTHON_BIN" visualization/soc_wall.py > logs/runtime/soc_wall.log 2>&1 &
echo $! > logs/runtime/soc_wall.pid
echo "✅ SOC Wall started (PID $(cat logs/runtime/soc_wall.pid))"

sleep 2

# -------------------------------------------------
# OPTIONAL: Control Center
# Uncomment if you want it always on
# -------------------------------------------------
# nohup "$PYTHON_BIN" visualization/control_center.py > logs/runtime/control_center.log 2>&1 &
# echo $! > logs/runtime/control_center.pid
# echo "✅ Control Center started (PID $(cat logs/runtime/control_center.pid))"

echo
echo "🎉 Aegis Demo Stack Started"
echo
echo "Open these URLs:"
echo "  Attack Lab:        http://127.0.0.1:7300"
echo "  Main Dashboard:    http://127.0.0.1:7000"
echo "  SOC Wall:          http://127.0.0.1:7500"
echo "  Control API:       http://127.0.0.1:7400/status"
echo "  Vulnerable Server: http://127.0.0.1:7200"
echo "  Federated Model:   https://127.0.0.1:8000/global_model"
echo
echo "📄 Logs:"
echo "  tail -f logs/runtime/main.log"
echo "  tail -f logs/runtime/federation.log"
echo "  tail -f logs/runtime/attack_simulator.log"
echo

