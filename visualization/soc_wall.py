from flask import Flask, render_template_string, jsonify
import json
import os
from collections import Counter

LOG_FILE = "logs/attacks.json"

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Aegis SOC Wall</title>
    <style>
        body{
            background:#000;
            color:#00ff9c;
            font-family:monospace;
            margin:0;
            padding:0;
        }

        .header{
            padding:16px 20px;
            border-bottom:1px solid #00ff9c;
            display:flex;
            justify-content:space-between;
            align-items:center;
            background:#050505;
        }

        .title{
            font-size:24px;
            font-weight:bold;
        }

        .status{
            font-size:14px;
            color:#88ffcc;
        }

        .grid{
            display:grid;
            grid-template-columns:2fr 1fr;
            grid-template-rows:50vh 50vh;
            height:calc(100vh - 64px);
            gap:0;
        }

        .panel{
            border:1px solid #00ff9c;
            padding:12px;
            overflow:auto;
            background:#030303;
        }

        .panel h2{
            margin:0 0 10px 0;
            font-size:18px;
            color:#00ff9c;
        }

        iframe{
            width:100%;
            height:calc(100% - 30px);
            border:none;
            background:#000;
        }

        pre{
            white-space:pre-wrap;
            word-wrap:break-word;
            font-size:13px;
            line-height:1.4;
            margin:0;
        }

        .empty{
            color:#66cc99;
            opacity:0.8;
        }

        .footer{
            position:fixed;
            bottom:8px;
            right:12px;
            font-size:12px;
            color:#66cc99;
            opacity:0.8;
            background:#000;
            padding:4px 8px;
            border:1px solid #00ff9c;
            border-radius:6px;
        }
    </style>
</head>
<body>

    <div class="header">
        <div class="title">🛡️ Aegis SOC Wall</div>
        <div class="status" id="statusText">Refreshing every 3s...</div>
    </div>

    <div class="grid">

        <div class="panel">
            <h2>🌍 Global Attack Map</h2>
            <iframe src="http://127.0.0.1:7100"></iframe>
        </div>

        <div class="panel">
            <h2>📊 Attack Statistics</h2>
            <pre id="stats" class="empty">Loading...</pre>
        </div>

        <div class="panel">
            <h2>🚨 Live Attack Feed</h2>
            <pre id="feed" class="empty">Loading...</pre>
        </div>

        <div class="panel">
            <h2>🔥 Blocked Attackers</h2>
            <pre id="blocked" class="empty">Loading...</pre>
        </div>

    </div>

    <div class="footer" id="lastUpdated">Last updated: --</div>

    <script>
        function pretty(obj){
            return JSON.stringify(obj, null, 2);
        }

        function setText(id, value){
            const el = document.getElementById(id);

            if (
                value === null ||
                value === undefined ||
                (Array.isArray(value) && value.length === 0) ||
                (typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0)
            ){
                el.textContent = "No data yet.";
                el.className = "empty";
                return;
            }

            el.textContent = pretty(value);
            el.className = "";
        }

        async function refreshPanels(){
            try{
                const [statsRes, feedRes, blockedRes] = await Promise.all([
                    fetch('/stats'),
                    fetch('/feed'),
                    fetch('/blocked')
                ]);

                const stats = await statsRes.json();
                const feed = await feedRes.json();
                const blocked = await blockedRes.json();

                setText("stats", stats);
                setText("feed", feed);
                setText("blocked", blocked);

                const now = new Date();
                document.getElementById("lastUpdated").textContent =
                    "Last updated: " + now.toLocaleTimeString();

                document.getElementById("statusText").textContent =
                    "Refreshing every 3s • LIVE";
            }catch(e){
                document.getElementById("stats").textContent = "Failed to load stats: " + e;
                document.getElementById("feed").textContent = "Failed to load feed: " + e;
                document.getElementById("blocked").textContent = "Failed to load blocked: " + e;

                document.getElementById("statusText").textContent =
                    "Refresh error";
            }
        }

        refreshPanels();
        setInterval(refreshPanels, 3000);
    </script>

</body>
</html>
"""


def read_logs():
    """
    Read newline-delimited JSON attack logs safely.
    Returns a list of parsed events.
    """
    if not os.path.exists(LOG_FILE):
        return []

    logs = []

    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue

                try:
                    logs.append(json.loads(line))
                except Exception:
                    # Skip malformed lines instead of crashing
                    continue

    except Exception as e:
        print(f"[SOC WALL] Failed to read logs: {e}")
        return []

    return logs


@app.route("/")
def home():
    return render_template_string(HTML)


@app.route("/stats")
def stats():
    logs = read_logs()

    event_counter = Counter()
    blocked_counter = 0
    suspicious_counter = 0

    for entry in logs:
        event_name = entry.get("event", "UNKNOWN")
        event_counter[event_name] += 1

        if event_name == "BLOCKED_ATTACKER":
            blocked_counter += 1

        if event_name == "SUSPICIOUS_ACTIVITY":
            suspicious_counter += 1

    return jsonify({
        "total_events": len(logs),
        "blocked_events": blocked_counter,
        "suspicious_events": suspicious_counter,
        "event_types": dict(event_counter)
    })


@app.route("/feed")
def feed():
    logs = read_logs()
    return jsonify(logs[-20:])


@app.route("/blocked")
def blocked():
    logs = read_logs()

    blocked_logs = [
        entry for entry in logs
        if entry.get("event") == ["BLOCKED_ATTACKER", "WOULD_BLOCK_ATTACKER"]
    ]

    return jsonify(blocked_logs[-20:])


if __name__ == "__main__":
    print("🛡️ Aegis SOC Wall running on port 7500")

    app.run(
        host="0.0.0.0",
        port=7500,
        debug=False,
        use_reloader=False
    )
