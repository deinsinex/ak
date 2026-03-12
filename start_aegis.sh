#!/bin/bash

# ======================================
# AEGIS AI FIREWALL - FULL SOC LAB LAUNCHER
# Debian VM / XFCE compatible
# ======================================

set -u

PROJECT_DIR="/home/akshay/edge_ml"
PYTHON_BIN="/home/akshay/federated_env/bin/python"

export PYTHONPATH="$PROJECT_DIR"

cd "$PROJECT_DIR" || {
    echo "❌ Failed to enter project directory: $PROJECT_DIR"
    exit 1
}

# ======================================
# Helpers
# ======================================

print_header() {
    echo ""
    echo "======================================"
    echo "     AEGIS AI FIREWALL SOC LAB"
    echo "======================================"
    echo ""
}

print_footer() {
    echo ""
    echo "======================================"
    echo " AEGIS SOC LAB STARTED"
    echo "======================================"
    echo ""
    echo "Control Center:"
    echo "http://localhost:7600"
    echo ""
    echo "Firewall Dashboard:"
    echo "http://localhost:7000"
    echo ""
    echo "3D Attack Globe:"
    echo "http://localhost:7100"
    echo ""
    echo "SOC Wall:"
    echo "http://localhost:7500"
    echo ""
    echo "Attack Lab:"
    echo "http://localhost:7300"
    echo ""
    echo "Threat Intelligence Feed:"
    echo "http://localhost:8200"
    echo ""
    echo "Federated Model:"
    echo "http://localhost:8000/global_model"
    echo ""
    echo "Vulnerable Test Server:"
    echo "http://localhost:5001"
    echo ""
    echo "======================================"
    echo ""
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

launch_terminal() {
    local title="$1"
    local cmd="$2"

    if command_exists xfce4-terminal; then
        xfce4-terminal --title="$title" --hold --working-directory="$PROJECT_DIR" --command="bash -c '$cmd; exec bash'" &
        return 0
    fi

    if command_exists gnome-terminal; then
        gnome-terminal --title="$title" -- bash -c "$cmd; exec bash" &
        return 0
    fi

    return 1
}

launch_background() {
    local name="$1"
    local cmd="$2"

    mkdir -p "$PROJECT_DIR/logs"

    echo "⚠️ No supported GUI terminal found. Starting $name in background..."
    nohup bash -c "$cmd" > "$PROJECT_DIR/logs/${name}.log" 2>&1 &
}

launch_service() {
    local name="$1"
    local cmd="$2"

    echo "▶ Starting $name..."

    if ! launch_terminal "$name" "$cmd"; then
        launch_background "$name" "$cmd"
    fi

    sleep 2
}

# ======================================
# Pre-flight checks
# ======================================

print_header

if [ ! -x "$PYTHON_BIN" ]; then
    echo "❌ Python interpreter not found:"
    echo "   $PYTHON_BIN"
    exit 1
fi

echo "✅ Using Python: $PYTHON_BIN"
echo "✅ Project dir: $PROJECT_DIR"
echo "✅ PYTHONPATH: $PYTHONPATH"
echo ""

# ======================================
# Optional dependency hints
# ======================================

if ! command_exists xfce4-terminal && ! command_exists gnome-terminal; then
    echo "⚠️ Neither xfce4-terminal nor gnome-terminal found."
    echo "   Services will launch in background mode."
    echo ""
fi

# ======================================
# Launch Order
# ======================================

# 1) Federated learning server
launch_service "Aegis Federation Server" \
"cd '$PROJECT_DIR' && export PYTHONPATH='$PROJECT_DIR' && '$PYTHON_BIN' federation/server.py"

# 2) Threat intel server
launch_service "Aegis Threat Intel Server" \
"cd '$PROJECT_DIR' && export PYTHONPATH='$PROJECT_DIR' && '$PYTHON_BIN' federation/threat_intel_server.py"

# 3) Vulnerable lab server
launch_service "Aegis Vulnerable Test Server" \
"cd '$PROJECT_DIR' && export PYTHONPATH='$PROJECT_DIR' && '$PYTHON_BIN' lab/vulnerable_server.py"

# 4) Main firewall engine
launch_service "Aegis AI Firewall Engine" \
"cd '$PROJECT_DIR' && export PYTHONPATH='$PROJECT_DIR' && '$PYTHON_BIN' main.py"

# 5) Firewall dashboard
launch_service "Aegis Firewall Dashboard" \
"cd '$PROJECT_DIR' && export PYTHONPATH='$PROJECT_DIR' && '$PYTHON_BIN' visualization/dashboard_server.py"

# 6) 3D globe
launch_service "Aegis 3D SOC Globe" \
"cd '$PROJECT_DIR' && export PYTHONPATH='$PROJECT_DIR' && '$PYTHON_BIN' visualization/soc_globe.py"

# 7) SOC wall
launch_service "Aegis SOC Wall" \
"cd '$PROJECT_DIR' && export PYTHONPATH='$PROJECT_DIR' && '$PYTHON_BIN' visualization/soc_wall.py"

# 8) Control center
launch_service "Aegis Control Center" \
"cd '$PROJECT_DIR' && export PYTHONPATH='$PROJECT_DIR' && '$PYTHON_BIN' visualization/control_center.py"

# 9) Attack lab
launch_service "Aegis Attack Lab" \
"cd '$PROJECT_DIR' && export PYTHONPATH='$PROJECT_DIR' && '$PYTHON_BIN' visualization/attack_simulator.py"

print_footer
