from flask import Flask, render_template_string
import json
import os

LOG_FILE = "logs/attacks.json"

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>

<title>Aegis SOC Wall</title>

<style>

body{
background:black;
color:#00ff9c;
font-family:monospace;
margin:0;
}

.grid{
display:grid;
grid-template-columns:2fr 1fr;
grid-template-rows:50vh 50vh;
height:100vh;
}

.panel{
border:1px solid #00ff9c;
padding:10px;
overflow:auto;
}

iframe{
width:100%;
height:100%;
border:none;
}

h2{
margin-top:0;
}

</style>

<meta http-equiv="refresh" content="5">

</head>

<body>

<div class="grid">

<div class="panel">
<h2>🌍 Global Attack Map</h2>
<iframe src="http://localhost:7100"></iframe>
</div>

<div class="panel">
<h2>📊 Attack Statistics</h2>
<pre id="stats"></pre>
</div>

<div class="panel">
<h2>🚨 Live Attack Feed</h2>
<pre id="feed"></pre>
</div>

<div class="panel">
<h2>🔥 Blocked Attackers</h2>
<pre id="blocked"></pre>
</div>

</div>

<script>

fetch('/stats')
.then(r=>r.json())
.then(data=>{

document.getElementById("stats").textContent =
JSON.stringify(data,null,2);

})

fetch('/feed')
.then(r=>r.json())
.then(data=>{

document.getElementById("feed").textContent =
JSON.stringify(data,null,2);

})

fetch('/blocked')
.then(r=>r.json())
.then(data=>{

document.getElementById("blocked").textContent =
JSON.stringify(data,null,2);

})

</script>

</body>
</html>
"""


def read_logs():

    if not os.path.exists(LOG_FILE):
        return []

    logs = []

    with open(LOG_FILE) as f:

        for line in f.readlines():

            try:
                logs.append(json.loads(line))
            except:
                pass

    return logs


@app.route("/")
def home():

    return render_template_string(HTML)


@app.route("/stats")
def stats():

    logs = read_logs()

    total = len(logs)

    types = {}

    for l in logs:

        e = l.get("event")

        types[e] = types.get(e,0)+1

    return {
        "total_events": total,
        "event_types": types
    }


@app.route("/feed")
def feed():

    logs = read_logs()

    return logs[-20:]


@app.route("/blocked")
def blocked():

    logs = read_logs()

    blocked = [l for l in logs if l.get("event")=="BLOCKED_ATTACKER"]

    return blocked[-20:]


if __name__ == "__main__":

    print("SOC Wall running on port 7500")

    app.run(
        host="0.0.0.0",
        port=7500
    )
