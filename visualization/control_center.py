from flask import Flask, render_template_string
import requests


app = Flask(__name__)

CONTROL_API = "http://localhost:7400"


HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Aegis Control Center</title>

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
font-size:40px;
margin-top:20px;
}

.status{
border:1px solid #00ff9c;
padding:20px;
margin:20px auto;
width:80%;
max-width:900px;
background:#050505;
}

.grid{
display:grid;
grid-template-columns:repeat(3,1fr);
gap:20px;
padding:20px;
max-width:1200px;
margin:0 auto;
}

.card{
border:1px solid #00ff9c;
padding:25px;
cursor:pointer;
transition:0.3s;
background:#080808;
}

.card:hover{
background:#00ff9c;
color:black;
}

button{
background:#111;
color:#00ff9c;
border:1px solid #00ff9c;
padding:15px 25px;
margin:10px;
font-size:16px;
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
}
</style>

<meta http-equiv="refresh" content="5">
</head>
<body>

<h1>🛡️ Aegis AI Security Platform</h1>

<div class="status">
<h2>🎛️ Live Firewall Control</h2>

<button onclick="fetch('/api/detect').then(()=>location.reload())">DETECT MODE</button>
<button onclick="fetch('/api/protect').then(()=>location.reload())">PROTECT MODE</button>
<button onclick="fetch('/api/toggle').then(()=>location.reload())">TOGGLE MODE</button>
<button onclick="if(confirm('Reset memory and unblock all?')) fetch('/api/reset').then(()=>location.reload())">RESET + UNBLOCK ALL</button>

<h3>Current Status</h3>
<pre>{{ status_text }}</pre>
</div>

<div class="grid">

<div class="card" onclick="window.open('http://localhost:7500', '_blank')">
<h2>SOC Wall</h2>
<p>Security Operations Dashboard</p>
</div>

<div class="card" onclick="window.open('http://localhost:7100', '_blank')">
<h2>Attack Globe</h2>
<p>Global cyber attack visualization</p>
</div>

<div class="card" onclick="window.open('http://localhost:7300', '_blank')">
<h2>Attack Lab</h2>
<p>Simulate cyber attacks</p>
</div>

<div class="card" onclick="window.open('http://localhost:7000', '_blank')">
<h2>Firewall Dashboard</h2>
<p>Live firewall telemetry</p>
</div>

<div class="card" onclick="window.open('http://localhost:8100/threat_feed', '_blank')">
<h2>Threat Intelligence</h2>
<p>Collaborative threat feed</p>
</div>

<div class="card" onclick="window.open('https://localhost:8000/global_model', '_blank')">
<h2>Federated AI</h2>
<p>Global AI model</p>
</div>

</div>

</body>
</html>
"""


def get_status():
    try:
        r = requests.get(f"{CONTROL_API}/status", timeout=2)

        if r.status_code == 200:
            data = r.json()

            lines = [
                f"Mode: {data.get('mode', 'unknown').upper()}",
                f"Protection Enabled: {data.get('protection_enabled')}",
                f"Active Block Count: {data.get('active_block_count')}",
                f"Active Blocks: {data.get('active_blocks')}",
                f"Known Attackers in Memory: {data.get('known_attackers')}",
                f"Threat DB Entries: {data.get('threat_db_entries')}"
            ]

            return "\n".join(lines)

        return f"Control API error: HTTP {r.status_code}"

    except Exception as e:
        return f"Control API unavailable: {e}"


@app.route("/")
def home():
    return render_template_string(HTML, status_text=get_status())


@app.route("/api/detect")
def api_detect():
    try:
        requests.get(f"{CONTROL_API}/mode/detect", timeout=2)
    except Exception:
        pass
    return ("", 204)


@app.route("/api/protect")
def api_protect():
    try:
        requests.get(f"{CONTROL_API}/mode/protect", timeout=2)
    except Exception:
        pass
    return ("", 204)


@app.route("/api/toggle")
def api_toggle():
    try:
        requests.get(f"{CONTROL_API}/mode/toggle", timeout=2)
    except Exception:
        pass
    return ("", 204)


@app.route("/api/reset")
def api_reset():
    try:
        requests.get(f"{CONTROL_API}/reset", timeout=5)
    except Exception:
        pass
    return ("", 204)


if __name__ == "__main__":
    print("🎛️ Aegis Control Center running on port 7600")

    app.run(
        host="0.0.0.0",
        port=7600,
        debug=False,
        use_reloader=False
    )
