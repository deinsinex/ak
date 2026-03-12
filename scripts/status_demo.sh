#!/usr/bin/env bash

echo "📊 Aegis Demo Stack Status"
echo

for svc in \
  "python -m federation.server" \
  "lab/vulnerable_server.py" \
  "python main.py" \
  "python -m visualization.attack_simulator" \
  "python visualization/soc_wall.py"
do
  if pgrep -af "$svc" >/dev/null; then
    echo "✅ RUNNING: $svc"
  else
    echo "❌ NOT RUNNING: $svc"
  fi
done
