from flask import Flask, render_template_string
import json
import os
import time

from core.traffic_monitor import TrafficMonitor

app = Flask(__name__)

LOG_FILE = "logs/attacks.json"

monitor = TrafficMonitor()


HTML = """
<!DOCTYPE html>
<html>

<head>

<title>Aegis AI Firewall SOC</title>

<meta http-equiv="refresh" content="5">

<style>

body{
background:#0d1117;
color:#00ff9c;
font-family:monospace;
text-align:center;
}

.container{
width:90%;
margin:auto;
}

.card{
background:#161b22;
padding:20px;
margin:10px;
border-radius:10px;
}

.grid{
display:grid;
grid-template-columns:repeat(3,1fr);
gap:10px;
}

h1{
margin-top:20px;
}

iframe{
width:100%;
height:400px;
border:none;
}

</style>

</head>

<body>

<h1>🛡️ Aegis AI Firewall SOC</h1>

<div class="container">

<div class="grid">

<div class="card">
<h2>Packets/sec</h2>
<h3>{{pps}}</h3>
</div>

<div class="card">
<h2>Total Packets</h2>
<h3>{{packets}}</h3>
</div>

<div class="card">
<h2>Attack Events</h2>
<h3>{{attacks}}</h3>
</div>

<div class="card">
<h2>Active IPs</h2>
<h3>{{ips}}</h3>
</div>

</div>

<div class="card">
<h2>Live Attack Map</h2>
<iframe src="/map"></iframe>
</div>

<div class="card">
<h2>Recent Alerts</h2>
<pre>{{alerts}}</pre>
</div>

</div>

</body>

</html>
"""


def read_alerts():

    if not os.path.exists(LOG_FILE):
        return "No alerts yet."

    lines = []

    with open(LOG_FILE) as f:

        for line in f.readlines()[-10:]:

            try:

                entry = json.loads(line)

                lines.append(
                    f"{entry['timestamp']}  {entry['ip']}  {entry['event']}"
                )

            except:
                pass

    return "\n".join(lines)


@app.route("/")
def home():

    stats = monitor.stats()

    alerts = read_alerts()

    return render_template_string(

        HTML,

        pps=stats["packets_per_sec"],

        packets=stats["total_packets"],

        attacks=stats["attack_events"],

        ips=stats["active_ips"],

        alerts=alerts
    )


@app.route("/map")
def map_view():

    from visualization.attack_map import build_attack_map

    world_map = build_attack_map()

    return world_map._repr_html_()


def start_attack_dashboard():

    print("🌍 SOC Dashboard running on port 7000")

    app.run(
        host="0.0.0.0",
        port=7000,
        debug=False,
        use_reloader=False
    )
