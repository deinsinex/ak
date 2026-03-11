from flask import Flask, render_template_string

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>

<head>

<title>Aegis Security Platform</title>

<style>

body{
background:black;
color:#00ff9c;
font-family:monospace;
text-align:center;
}

h1{
font-size:40px;
margin-top:40px;
}

.grid{
display:grid;
grid-template-columns:repeat(3,1fr);
gap:30px;
padding:50px;
}

.card{

border:1px solid #00ff9c;
padding:40px;
cursor:pointer;
transition:0.3s;

}

.card:hover{

background:#00ff9c;
color:black;

}

</style>

</head>

<body>

<h1>🛡️ Aegis AI Security Platform</h1>

<div class="grid">

<div class="card" onclick="window.open('http://localhost:7500')">

<h2>SOC Wall</h2>
<p>Security Operations Dashboard</p>

</div>

<div class="card" onclick="window.open('http://localhost:7100')">

<h2>Attack Globe</h2>
<p>Global cyber attack visualization</p>

</div>

<div class="card" onclick="window.open('http://localhost:7300')">

<h2>Attack Lab</h2>
<p>Simulate cyber attacks</p>

</div>

<div class="card" onclick="window.open('http://localhost:7000')">

<h2>Firewall Dashboard</h2>
<p>Live firewall telemetry</p>

</div>

<div class="card" onclick="window.open('http://localhost:8200')">

<h2>Threat Intelligence</h2>
<p>Collaborative threat feed</p>

</div>

<div class="card" onclick="window.open('http://localhost:8000/global_model')">

<h2>Federated AI</h2>
<p>Global AI model</p>

</div>

</div>

</body>

</html>
"""

@app.route("/")
def home():
    return render_template_string(HTML)


if __name__ == "__main__":

    print("Aegis Control Center running on port 7600")

    app.run(
        host="0.0.0.0",
        port=7600
    )
