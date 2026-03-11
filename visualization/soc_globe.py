from flask import Flask, render_template_string
import json
import os

LOG_FILE = "logs/attacks.json"

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>

<title>Aegis Cyber Globe</title>

<style>
body {
background:black;
margin:0;
overflow:hidden;
}

canvas {
display:block;
}

#title {
position:absolute;
top:10px;
left:20px;
color:#00ff9c;
font-family:monospace;
font-size:24px;
}
</style>

<script src="https://unpkg.com/three@0.150.1/build/three.min.js"></script>
<script src="https://unpkg.com/three-globe"></script>

</head>

<body>

<div id="title">🌍 Aegis Cyber Attack Globe</div>

<script>

fetch('/data')
.then(r=>r.json())
.then(attacks=>{

const Globe = new ThreeGlobe()
.globeImageUrl('https://unpkg.com/three-globe/example/img/earth-dark.jpg')
.arcsData(attacks)
.arcColor(()=> '#ff0000')
.arcAltitude(0.2)
.arcStroke(0.5)

const renderer = new THREE.WebGLRenderer();
renderer.setSize(window.innerWidth, window.innerHeight);
document.body.appendChild(renderer.domElement);

const scene = new THREE.Scene();
scene.add(Globe);

const camera = new THREE.PerspectiveCamera();
camera.aspect = window.innerWidth/window.innerHeight;
camera.updateProjectionMatrix();
camera.position.z = 300;

const animate = ()=>{
requestAnimationFrame(animate);
Globe.rotation.y += 0.001;
renderer.render(scene,camera);
};

animate();

});

</script>

</body>
</html>
"""


def read_attacks():

    if not os.path.exists(LOG_FILE):
        return []

    arcs = []

    with open(LOG_FILE) as f:

        for line in f.readlines()[-100:]:

            try:

                entry = json.loads(line)

                geo = entry.get("geo")

                if not geo:
                    continue

                lat = geo.get("lat")
                lon = geo.get("lon")

                if lat is None or lon is None:
                    continue

                arcs.append({

                    "startLat": lat,
                    "startLng": lon,
                    "endLat": 20,
                    "endLng": 78

                })

            except:
                pass

    return arcs


@app.route("/")
def home():
    return render_template_string(HTML)


@app.route("/data")
def data():
    return read_attacks()


if __name__ == "__main__":

    print("🌍 Cyber Attack Globe running on port 7100")

    app.run(
        host="0.0.0.0",
        port=7100
    )
