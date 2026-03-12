from flask import Flask, render_template_string, jsonify
import threading

from lab.namespace_lab import (
    setup_lab,
    destroy_lab,
    lab_status,
    http_burst,
    payload_attack,
    login_bruteforce,
    port_scan,
    syn_burst,
    mixed_attack_all
)

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>

<title>Aegis Attack Lab</title>

<style>

body{
background:black;
color:#00ff9c;
font-family:monospace;
text-align:center;
margin:0;
padding:0;
}

h1{
margin-top:30px;
font-size:36px;
}

.container{
padding:30px;
max-width:1200px;
margin:auto;
}

.grid{
display:grid;
grid-template-columns:repeat(3,1fr);
gap:20px;
margin-top:30px;
}

button{
background:#111;
color:#00ff9c;
border:1px solid #00ff9c;
padding:18px;
font-size:16px;
cursor:pointer;
width:100%;
border-radius:8px;
transition:0.3s;
}

button:hover{
background:#00ff9c;
color:black;
}

.panel{
margin-top:30px;
border:1px solid #00ff9c;
padding:20px;
text-align:left;
border-radius:8px;
background:#050505;
}

pre{
white-space:pre-wrap;
word-wrap:break-word;
font-size:14px;
}

.note{
margin-top:20px;
color:#88ffcc;
font-size:14px;
}

</style>

</head>

<body>

<div class="container">

<h1>⚔️ Aegis Real Multi-IP Attack Lab</h1>

<div class="grid">

<button onclick="callApi('/lab/setup')">🧪 Setup Lab</button>
<button onclick="callApi('/lab/destroy')">🧹 Destroy Lab</button>
<button onclick="callApi('/lab/status')">📡 Lab Status</button>

<button onclick="callApi('/attack/portscan')">🛰️ Port Scan (bot1)</button>
<button onclick="callApi('/attack/payload')">💣 Payload Attack (bot2)</button>
<button onclick="callApi('/attack/bruteforce')">🔐 Login Bruteforce (bot3)</button>

<button onclick="callApi('/attack/synburst')">⚡ SYN Burst (bot4)</button>
<button onclick="callApi('/attack/httpburst')">🌐 HTTP Burst (bot1)</button>
<button onclick="callApi('/attack/mixed')">🔥 Full Multi-IP Botnet Attack</button>

</div>

<div class="panel">
<h2>📋 Result</h2>
<pre id="result">Ready.</pre>
</div>

<div class="note">
Target vulnerable server expected at: <b>http://10.200.1.1:7200</b><br>
Make sure Aegis is running before launching attacks.
</div>

</div>

<script>
async function callApi(path){
    try{
        const r = await fetch(path);
        const data = await r.json();
        document.getElementById("result").textContent = JSON.stringify(data, null, 2);
    }catch(e){
        document.getElementById("result").textContent = "Request failed: " + e;
    }
}
</script>

</body>
</html>
"""


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():
    return render_template_string(HTML)


# =========================================================
# LAB MANAGEMENT
# =========================================================

@app.route("/lab/setup")
def route_setup_lab():
    try:
        setup_lab()

        return jsonify({
            "status": "ok",
            "message": "Namespace lab setup complete",
            "lab": lab_status()
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/lab/destroy")
def route_destroy_lab():
    try:
        destroy_lab()

        return jsonify({
            "status": "ok",
            "message": "Namespace lab destroyed"
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/lab/status")
def route_lab_status():
    try:
        return jsonify({
            "status": "ok",
            "lab": lab_status()
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# =========================================================
# ATTACK ROUTES
# =========================================================

@app.route("/attack/portscan")
def route_portscan():
    try:
        threading.Thread(
            target=lambda: port_scan("bot1"),
            daemon=True
        ).start()

        return jsonify({
            "status": "ok",
            "message": "Port scan launched from bot1 (10.200.1.11)"
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/attack/payload")
def route_payload():
    try:
        threading.Thread(
            target=lambda: payload_attack("bot2"),
            daemon=True
        ).start()

        return jsonify({
            "status": "ok",
            "message": "Payload attack launched from bot2 (10.200.1.12)"
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/attack/bruteforce")
def route_bruteforce():
    try:
        threading.Thread(
            target=lambda: login_bruteforce("bot3", attempts=20),
            daemon=True
        ).start()

        return jsonify({
            "status": "ok",
            "message": "Login brute-force launched from bot3 (10.200.1.13)"
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/attack/synburst")
def route_synburst():
    try:
        threading.Thread(
            target=lambda: syn_burst("bot4", count=50),
            daemon=True
        ).start()

        return jsonify({
            "status": "ok",
            "message": "SYN burst launched from bot4 (10.200.1.14)"
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/attack/httpburst")
def route_httpburst():
    try:
        threading.Thread(
            target=lambda: http_burst("bot1", count=40),
            daemon=True
        ).start()

        return jsonify({
            "status": "ok",
            "message": "HTTP burst launched from bot1 (10.200.1.11)"
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/attack/mixed")
def route_mixed():
    try:
        threading.Thread(
            target=mixed_attack_all,
            daemon=True
        ).start()

        return jsonify({
            "status": "ok",
            "message": "Full multi-IP mixed botnet attack launched"
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    print("⚔️ Aegis Real Attack Simulator running on port 7300")

    app.run(
        host="0.0.0.0",
        port=7300,
        debug=False,
        use_reloader=False
    )
