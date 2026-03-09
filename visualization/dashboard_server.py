from flask import Flask, render_template_string, request, jsonify
import json
import os
import time

from visualization.attack_map import build_attack_map
from visualization.attack_simulator import (
    run_port_scan,
    run_stealth_scan,
    run_payload_attack,
    run_multi_stage_attack
)

from core.traffic_monitor import TrafficMonitor


app = Flask(__name__)

traffic_monitor = TrafficMonitor()

LOG_FILE = "logs/attacks.json"


HTML = """
<!DOCTYPE html>
<html>
<head>

<title>Aegis AI Firewall Dashboard</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>

body{
background:black;
color:#00ff9c;
font-family:monospace;
text-align:center;
}

button{
padding:10px;
margin:10px;
background:#111;
color:#00ff9c;
border:1px solid #00ff9c;
}

canvas{
background:#111;
margin-top:20px;
}

iframe{
width:90%;
height:400px;
border:none;
}

</style>

</head>

<body>

<h1>🛡️ Aegis AI Firewall Control Center</h1>

<h2>Attack Simulator</h2>

<form method="POST">
<button name="attack" value="scan">Run Port Scan</button>
<button name="attack" value="stealth">Run Stealth Scan</button>
<button name="attack" value="payload">Run Payload Attack</button>
<button name="attack" value="multi">Run Multi Stage Attack</button>
</form>

<h2>Live Attack Map</h2>

<iframe src="/map"></iframe>

<h2>Network Traffic</h2>

<canvas id="trafficChart" width="800" height="200"></canvas>

<h2>Recent Attacks</h2>

<pre>{{logs}}</pre>

<script>

const ctx = document.getElementById('trafficChart');

const chart = new Chart(ctx, {
type: 'line',
data: {
labels: [],
datasets: [{
label: 'Packets/sec',
data: [],
borderColor: '#00ff9c',
fill: false
}]
},
options: {
scales: {
y: {beginAtZero: true}
}
}
});

function updateTraffic(){

fetch('/traffic')
.then(res => res.json())
.then(data => {

chart.data.labels.push(new Date().toLocaleTimeString());
chart.data.datasets[0].data.push(data.rate);

if(chart.data.labels.length > 20){
chart.data.labels.shift();
chart.data.datasets[0].data.shift();
}

chart.update();

});
}

setInterval(updateTraffic, 1000);

</script>

</body>
</html>
"""


@app.route("/", methods=["GET","POST"])
def dashboard():

    if request.method == "POST":

        attack = request.form.get("attack")

        if attack == "scan":
            run_port_scan()

        elif attack == "stealth":
            run_stealth_scan()

        elif attack == "payload":
            run_payload_attack()

        elif attack == "multi":
            run_multi_stage_attack()

    logs = ""

    if os.path.exists(LOG_FILE):

        with open(LOG_FILE) as f:

            lines = f.readlines()

            logs = "".join(lines[-10:])

    return render_template_string(HTML, logs=logs)


@app.route("/map")
def map_view():

    world_map = build_attack_map()

    return world_map._repr_html_()


@app.route("/traffic")
def traffic():

    return jsonify({
        "rate": traffic_monitor.get_rate()
    })


def start_attack_dashboard():

    print("🌍 Dashboard running on port 7000")

    app.run(
        host="0.0.0.0",
        port=7000,
        debug=False,
        use_reloader=False
    )
