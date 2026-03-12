#!/usr/bin/env bash

PROJECT_DIR="$HOME/edge_ml"

echo "🛑 Stopping Aegis Demo Stack..."

# Kill by pid files if present
for f in \
  "$PROJECT_DIR/logs/runtime/federation.pid" \
  "$PROJECT_DIR/logs/runtime/vulnerable.pid" \
  "$PROJECT_DIR/logs/runtime/main.pid" \
  "$PROJECT_DIR/logs/runtime/attack_simulator.pid" \
  "$PROJECT_DIR/logs/runtime/soc_wall.pid" \
  "$PROJECT_DIR/logs/runtime/control_center.pid"
do
  if [ -f "$f" ]; then
    PID=$(cat "$f")
    kill "$PID" 2>/dev/null || true
    rm -f "$f"
  fi
done

# Extra cleanup by process match
pkill -f "python -m federation.server" 2>/dev/null || true
pkill -f "lab/vulnerable_server.py" 2>/dev/null || true
pkill -f "python main.py" 2>/dev/null || true
pkill -f "python -m visualization.attack_simulator" 2>/dev/null || true
pkill -f "python visualization/soc_wall.py" 2>/dev/null || true
pkill -f "python visualization/control_center.py" 2>/dev/null || true

echo "✅ Aegis Demo Stack stopped"
