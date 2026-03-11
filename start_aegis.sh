#!/bin/bash

echo ""
echo "======================================"
echo "     AEGIS AI SECURITY PLATFORM"
echo "======================================"
echo ""

echo "Starting Federation Server..."

gnome-terminal -- bash -c "cd federation; python server.py; exec bash"

sleep 2

echo "Starting Threat Intel Server..."

gnome-terminal -- bash -c "cd federation; python threat_intel_server.py; exec bash"

sleep 2

echo "Starting AI Firewall..."

gnome-terminal -- bash -c "cd ..; sudo /home/akshay/federated_env/bin/python main.py; exec bash"

sleep 2

echo "Starting Firewall Dashboard..."

gnome-terminal -- bash -c "cd visualization; python dashboard_server.py; exec bash"

sleep 2

echo "Starting Attack Globe..."

gnome-terminal -- bash -c "cd visualization; python soc_globe.py; exec bash"

sleep 2

echo "Starting Attack Lab..."

gnome-terminal -- bash -c "cd visualization; python attack_simulator.py; exec bash"

sleep 2

echo "Starting SOC Wall..."

gnome-terminal -- bash -c "cd visualization; python soc_wall.py; exec bash"

sleep 2

echo "Starting Control Center..."

gnome-terminal -- bash -c "cd visualization; python control_center.py; exec bash"

echo ""
echo "======================================"
echo " PLATFORM READY"
echo ""
echo "Control Center:"
echo "http://localhost:7600"
echo ""
echo "SOC Wall:"
echo "http://localhost:7500"
echo ""
echo "Attack Lab:"
echo "http://localhost:7300"
echo ""
echo "Attack Globe:"
echo "http://localhost:7100"
echo "======================================"
