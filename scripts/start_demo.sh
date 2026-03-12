#!/usr/bin/env bash
set -u

ROOT_DIR="$HOME/edge_ml"
cd "$ROOT_DIR" || exit 1

# ---------------------------------------------------------
# CONFIG
# ---------------------------------------------------------
FED_PID_FILE=".federation_server.pid"
THREAT_PID_FILE=".threat_intel_server.pid"
VULN_PID_FILE=".vuln_server.pid"
ATTACK_PID_FILE=".attack_simulator.pid"
SOC_PID_FILE=".soc_wall.pid"

FED_LOG="$ROOT_DIR/federation_server.log"
THREAT_LOG="$ROOT_DIR/threat_intel_server.log"
VULN_LOG="$ROOT_DIR/vulnerable_server.log"
ATTACK_LOG="$ROOT_DIR/attack_simulator.log"
SOC_LOG="$ROOT_DIR/soc_wall.log"

# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------
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

get_python_bin() {
  if [[ -n "${VIRTUAL_ENV:-}" && -x "${VIRTUAL_ENV}/bin/python" ]]; then
    echo "${VIRTUAL_ENV}/bin/python"
  else
    command -v python
  fi
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

wait_for_port() {
  local port="$1"
  local retries="${2:-20}"

  for _ in $(seq 1 "$retries"); do
    if lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done

  return 1
}

open_url() {
  local url="$1"
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url" >/dev/null 2>&1 &
    echo "🌐 Opened: $url"
  else
    echo "🌐 URL: $url"
  fi
}

start_python_service() {
  local label="$1"
  local module="$2"
  local port="$3"
  local log_file="$4"
  local pid_file="$5"

  local PY_BIN
  PY_BIN="$(get_python_bin)"

  echo "▶️ Starting $label ($port)..."
  : > "$log_file"

  nohup "$PY_BIN" -m "$module" >> "$log_file" 2>&1 &
  local pid=$!
  echo "$pid" > "$pid_file"

  if wait_for_port "$port" 20; then
    echo "✅ $label ($port) started (PID $pid)"
  else
    echo "❌ $label ($port) failed to start. Check log: $log_file"
  fi
}

# ---------------------------------------------------------
# STARTUP HEADER
# ---------------------------------------------------------
print_header "🛡️ AEGIS AI FIREWALL DEMO STARTUP"

# ---------------------------------------------------------
# STOP OLD STACK (background services only)
# ---------------------------------------------------------
stop_pid_file "$FED_PID_FILE" "Federation Server"
stop_pid_file "$THREAT_PID_FILE" "Threat Intel Server"
stop_pid_file "$VULN_PID_FILE" "Vulnerable Server"
stop_pid_file "$ATTACK_PID_FILE" "Attack Simulator"
stop_pid_file "$SOC_PID_FILE" "SOC Wall"

# ---------------------------------------------------------
# AGGRESSIVELY CLEAR NON-MAIN PORTS
# (Do NOT touch 7000/7400 here because main.py owns them manually)
# ---------------------------------------------------------
for port in 8000 8100 7200 7300 7500; do
  pids="$(lsof -tiTCP:$port -sTCP:LISTEN 2>/dev/null || true)"
  if [[ -n "$pids" ]]; then
    echo "🧹 Clearing stale listener(s) on port $port: $pids"
    kill $pids 2>/dev/null || true
    sleep 0.5
    pids2="$(lsof -tiTCP:$port -sTCP:LISTEN 2>/dev/null || true)"
    if [[ -n "$pids2" ]]; then
      kill -9 $pids2 2>/dev/null || true
    fi
  fi
done

# ---------------------------------------------------------
# FIX RUNTIME FILES / PERMISSIONS
# ---------------------------------------------------------
echo "🔧 Fixing runtime file permissions..."
mkdir -p federation
touch federation/threat_feed.json
chmod 664 federation/threat_feed.json 2>/dev/null || true

mkdir -p data 2>/dev/null || true
touch data/threat_memory.json 2>/dev/null || true
chmod 664 data/threat_memory.json 2>/dev/null || true

# ---------------------------------------------------------
# START BACKGROUND SERVICES
# ---------------------------------------------------------
echo
echo "⚠️ main.py is NOT auto-started (recommended for reliability)."
echo "ℹ️ Start main.py manually in a second terminal with sudo."

start_python_service "Federated Server" "federation.server" 8000 "$FED_LOG" "$FED_PID_FILE"
start_python_service "Threat Intel Server" "federation.threat_intel_server" 8100 "$THREAT_LOG" "$THREAT_PID_FILE"
start_python_service "Vulnerable Test Server" "lab.vulnerable_server" 7200 "$VULN_LOG" "$VULN_PID_FILE"
start_python_service "Attack Simulator" "visualization.attack_simulator" 7300 "$ATTACK_LOG" "$ATTACK_PID_FILE"
start_python_service "SOC Wall" "visualization.soc_wall" 7500 "$SOC_LOG" "$SOC_PID_FILE"

# ---------------------------------------------------------
# OPEN PAGES (only if ports are live)
# ---------------------------------------------------------
print_header "🌐 OPENING DEMO PAGES"

# main.py pages (7000/7400) only if already running manually
if lsof -iTCP:7000 -sTCP:LISTEN >/dev/null 2>&1; then open_url "http://127.0.0.1:7000"; fi
if wait_for_port 7300 2; then open_url "http://127.0.0.1:7300"; fi
if lsof -iTCP:7400 -sTCP:LISTEN >/dev/null 2>&1; then open_url "http://127.0.0.1:7400/status"; fi
if wait_for_port 7500 2; then open_url "http://127.0.0.1:7500"; fi
if wait_for_port 8000 2; then open_url "https://127.0.0.1:8000/global_model"; fi
if wait_for_port 8100 2; then open_url "https://127.0.0.1:8100/health"; fi

# ---------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------
print_header "✅ AEGIS DEMO STACK STARTUP COMPLETE"

echo "Background Services:"
echo " - Attack Simulator:     http://127.0.0.1:7300"
echo " - SOC Wall:             http://127.0.0.1:7500"
echo " - Federated Server:     https://127.0.0.1:8000/global_model"
echo " - Threat Intel Server:  https://127.0.0.1:8100/health"
echo " - Vulnerable Server:    http://10.200.1.1:7200  (after lab setup)"
echo
echo "Main Firewall (manual):"
echo " - Dashboard:            http://127.0.0.1:7000"
echo " - Control API Status:   http://127.0.0.1:7400/status"
echo
echo "RUN THIS IN A SECOND TERMINAL:"
echo "   sudo $(get_python_bin) $ROOT_DIR/main.py"
echo
echo "Logs:"
echo " - $FED_LOG"
echo " - $THREAT_LOG"
echo " - $VULN_LOG"
echo " - $ATTACK_LOG"
echo " - $SOC_LOG"
echo " - $ROOT_DIR/aegis_main.log"
echo
echo "Tip:"
echo " - First run this script."
echo " - Then run main.py manually with sudo in another terminal."
echo " - Then use Attack Simulator -> Setup Lab first, then launch attacks."
