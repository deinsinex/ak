#!/usr/bin/env bash
set -u

ROOT_DIR="$HOME/edge_ml"
cd "$ROOT_DIR" || exit 1

FED_PID_FILE=".federation_server.pid"
THREAT_PID_FILE=".threat_intel_server.pid"
VULN_PID_FILE=".vuln_server.pid"
ATTACK_PID_FILE=".attack_simulator.pid"
SOC_PID_FILE=".soc_wall.pid"

print_header() {
  echo
  echo "========================================================="
  echo "$1"
  echo "========================================================="
}

is_pid_running() {
  local pid="$1"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

stop_pid_file() {
  local pid_file="$1"
  local label="$2"

  if [[ -f "$pid_file" ]]; then
    local pid
    pid="$(cat "$pid_file" 2>/dev/null || true)"

    if is_pid_running "$pid"; then
      echo "🛑 Stopping $label (PID $pid)..."
      kill "$pid" 2>/dev/null || true
      sleep 1

      if is_pid_running "$pid"; then
        kill -9 "$pid" 2>/dev/null || true
      fi
    fi

    rm -f "$pid_file"
  fi
}

kill_port() {
  local port="$1"
  local pids
  pids="$(lsof -tiTCP:$port -sTCP:LISTEN 2>/dev/null || true)"
  if [[ -n "$pids" ]]; then
    echo "🧹 Clearing listener(s) on port $port: $pids"
    kill $pids 2>/dev/null || true
    sleep 0.5
    local pids2
    pids2="$(lsof -tiTCP:$port -sTCP:LISTEN 2>/dev/null || true)"
    if [[ -n "$pids2" ]]; then
      kill -9 $pids2 2>/dev/null || true
    fi
  fi
}

print_header "🛑 AEGIS AI FIREWALL DEMO SHUTDOWN"

# PID-file-managed services
stop_pid_file "$FED_PID_FILE" "Federation Server"
stop_pid_file "$THREAT_PID_FILE" "Threat Intel Server"
stop_pid_file "$VULN_PID_FILE" "Vulnerable Server"
stop_pid_file "$ATTACK_PID_FILE" "Attack Simulator"
stop_pid_file "$SOC_PID_FILE" "SOC Wall"

# Kill manual main.py (python main.py only)
MAIN_PIDS="$(pgrep -af '/home/akshay/federated_env/bin/python.*main.py|python .*main.py' | awk '{print $1}' || true)"
if [[ -n "${MAIN_PIDS:-}" ]]; then
  echo "🛑 Killing main.py process(es):"
  echo "$MAIN_PIDS"
  kill $MAIN_PIDS 2>/dev/null || true
  sleep 1

  MAIN_PIDS2="$(pgrep -af '/home/akshay/federated_env/bin/python.*main.py|python .*main.py' | awk '{print $1}' || true)"
  if [[ -n "${MAIN_PIDS2:-}" ]]; then
    kill -9 $MAIN_PIDS2 2>/dev/null || true
  fi
fi

# Kill leftover wrapper shells that may still exist
WRAPPER_PIDS="$(pgrep -af "nohup .*main.py|bash -c .*main.py" | awk '{print $1}' || true)"
if [[ -n "${WRAPPER_PIDS:-}" ]]; then
  echo "🛑 Killing wrapper shell process(es):"
  echo "$WRAPPER_PIDS"
  kill $WRAPPER_PIDS 2>/dev/null || true
  sleep 1

  WRAPPER_PIDS2="$(pgrep -af "nohup .*main.py|bash -c .*main.py" | awk '{print $1}' || true)"
  if [[ -n "${WRAPPER_PIDS2:-}" ]]; then
    kill -9 $WRAPPER_PIDS2 2>/dev/null || true
  fi
fi

# Clear all known service ports
for port in 7000 7400 7200 7300 7500 8000 8100; do
  kill_port "$port"
done

echo "✅ Demo stack stopped"
