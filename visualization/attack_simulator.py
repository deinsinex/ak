from flask import Flask, render_template_string, jsonify
import threading
import os
import sys


# Make project root importable even when running:
# python visualization/attack_simulator.py
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


from lab.namespace_lab import setup_lab, destroy_lab, lab_status, http_burst, payload_attack, mixed_attack_all


app = Flask(__name__)


HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Aegis Real Multi-IP Attack Lab</title>

<style>
body{
background:black;
color:#00ff9c;
font-family:monospace;
text-align:center;
margin:0;
padding:20px;
}

h1{
margin-top:20px;
font-size:36px;
}

.section{
border:1px solid #00ff9c;
padding:20px;
margin:20px auto;
max-width:1100px;
background:#050505;
}

button{
background:#111;
color:#00ff9c;
border:1px solid #00ff9c;
padding:14px 18px;
margin:8px;
font-size:15px;
cursor:pointer;
}

button:hover{
background:#00ff9c;
color:black;
}

pre{
text-align:left;
white-space:pre-wrap;
word-wrap:break-word;
overflow:auto;
max-height:350px;
}
</style>

<meta http-equiv="refresh" content="5">
</head>
<body>

<h1>⚔️ Aegis REAL Multi-IP Attack Lab</h1>

<div class="section">
<h2>🧱 Namespace Lab Controls</h2>
<button onclick="fetch('/setup_lab').then(()=>location.reload())">SETUP LAB</button>
<button onclick="fetch('/destroy_lab').then(()=>location.reload())">DESTROY LAB</button>
<button onclick="fetch('/status_json').then(()=>location.reload())">REFRESH STATUS</button>
</div>

<div class="section">
<h2>🎯 Real Attack Actions</h2>
<button onclick="fetch('/attacker1_http').then(()=>location.reload())">Attacker1 HTTP Burst</button>
<button onclick="fetch('/attacker2_payload').then(()=>location.reload())">Attacker2 Payload Attack</button>
<button onclick="fetch('/attacker3_http').then(()=>location.reload())">Attacker3 HTTP Burst</button>
<button onclick="fetch('/mixed_once').then(()=>location.reload())">ALL Attackers Mixed Once</button>
</div>

<div class="section">
<h2>📡 Lab Status</h2>
<pre>{{ status_text }}</pre>
</div>

</body>
</html>
"""


def status_text():
    try:
        data = lab_status()
        return str(data)
    except Exception as e:
        return f"Status error: {e}"


@app.route("/")
def home():
    return render_template_string(
        HTML,
        status_text=status_text()
    )


@app.route("/status_json")
def status_json():
    return jsonify(lab_status())


@app.route("/setup_lab")
def route_setup_lab():
    return jsonify(setup_lab())


@app.route("/destroy_lab")
def route_destroy_lab():
    return jsonify(destroy_lab())


@app.route("/attacker1_http")
def route_attacker1_http():
    threading.Thread(
        target=lambda: http_burst(0, "http://10.200.1.1:7200"),
        daemon=True
    ).start()

    return "attacker1 http burst started"


@app.route("/attacker2_payload")
def route_attacker2_payload():
    threading.Thread(
        target=lambda: payload_attack(1, "http://10.200.2.1:7200"),
        daemon=True
    ).start()

    return "attacker2 payload attack started"


@app.route("/attacker3_http")
def route_attacker3_http():
    threading.Thread(
        target=lambda: http_burst(2, "http://10.200.3.1:7200"),
        daemon=True
    ).start()

    return "attacker3 http burst started"


@app.route("/mixed_once")
def route_mixed_once():
    threading.Thread(
        target=lambda: mixed_attack_all([
            "http://10.200.1.1:7200",
            "http://10.200.2.1:7200",
            "http://10.200.3.1:7200"
        ]),
        daemon=True
    ).start()

    return "mixed real multi-ip attack started"


if __name__ == "__main__":
    print("⚔️ Aegis REAL Multi-IP Attack Simulator running on port 7300")

    app.run(
        host="0.0.0.0",
        port=7300,
        debug=False,
        use_reloader=False
    )
