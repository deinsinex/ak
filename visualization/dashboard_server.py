from flask import Flask, render_template_string
from visualization.attack_map import build_attack_map


app = Flask(__name__)


HTML = """
<!DOCTYPE html>
<html>
<head>

<title>Aegis Firewall Attack Map</title>

<style>

body{
background-color:black;
color:#00ff9c;
font-family:monospace;
text-align:center;
}

h1{
margin-top:20px;
}

iframe{
width:90%;
height:600px;
border:none;
}

</style>

<meta http-equiv="refresh" content="10">

</head>

<body>

<h1>🛡️ Aegis AI Firewall — Live Attack Map</h1>

<iframe src="/map"></iframe>

</body>
</html>
"""


@app.route("/")
def home():
    return render_template_string(HTML)


@app.route("/map")
def map_view():

    try:

        world_map = build_attack_map()

        if world_map is None:
            return "<h2 style='color:red'>Map generation failed.</h2>"

        return world_map._repr_html_()

    except Exception as e:

        return f"<h2 style='color:red'>Map error: {str(e)}</h2>"


def start_attack_dashboard():

    print("🌍 Attack dashboard running on port 7000")

    app.run(
        host="0.0.0.0",
        port=7000,
        debug=False,
        use_reloader=False
    )
