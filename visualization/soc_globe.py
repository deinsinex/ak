from flask import Flask, render_template_string
import json
import os

LOG_FILE = "logs/attacks.json"

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>

<title>Aegis 3D Cyber Attack Globe</title>

<style>
body{
margin:0;
background:black;
overflow:hidden;
color:#00ff9c;
font-family:monospace;
}

#title{
position:absolute;
top:10px;
left:20px;
font-size:22px;
}

</style>

<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>

</head>

<body>

<div id="title">🛡️ Aegis AI Firewall — Global Attack Monitor</div>

<script>

let scene = new THREE.Scene();

let camera = new THREE.PerspectiveCamera(
75,
window.innerWidth/window.innerHeight,
0.1,
1000
);

let renderer = new THREE.WebGLRenderer();

renderer.setSize(window.innerWidth, window.innerHeight);

document.body.appendChild(renderer.domElement);


let geometry = new THREE.SphereGeometry(5, 64, 64);

let material = new THREE.MeshBasicMaterial({
color:0x0077ff,
wireframe:true
});

let globe = new THREE.Mesh(geometry, material);

scene.add(globe);

camera.position.z = 12;


function latLonToVector3(lat, lon, radius){

const phi = (90-lat)*(Math.PI/180)
const theta = (lon+180)*(Math.PI/180)

return new THREE.Vector3(
-(radius*Math.sin(phi)*Math.cos(theta)),
(radius*Math.cos(phi)),
(radius*Math.sin(phi)*Math.sin(theta))
)

}


function createAttackArc(srcLat,srcLon,dstLat,dstLon){

let start = latLonToVector3(srcLat,srcLon,5)
let end = latLonToVector3(dstLat,dstLon,5)

let material = new THREE.LineBasicMaterial({color:0xff0000})

let points = []

points.push(start)
points.push(end)

let geometry = new THREE.BufferGeometry().setFromPoints(points)

let line = new THREE.Line(geometry,material)

scene.add(line)

setTimeout(()=>scene.remove(line),3000)

}


function fetchAttacks(){

fetch("/attacks")
.then(res=>res.json())
.then(data=>{

data.forEach(a=>{

createAttackArc(
a.lat,
a.lon,
20,
0
)

})

})

}

setInterval(fetchAttacks,2000)


function animate(){

requestAnimationFrame(animate)

globe.rotation.y += 0.002

renderer.render(scene,camera)

}

animate()

</script>

</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/attacks")
def attacks():

    if not os.path.exists(LOG_FILE):
        return []

    results = []

    with open(LOG_FILE) as f:

        for line in f.readlines()[-10:]:

            try:

                entry = json.loads(line)

                geo = entry.get("geo")

                if not geo:
                    continue

                results.append({
                    "lat": geo.get("lat"),
                    "lon": geo.get("lon")
                })

            except:
                pass

    return results


def start_soc_globe():

    print("🌎 SOC 3D Globe running on port 7100")

    app.run(
        host="0.0.0.0",
        port=7100,
        debug=False,
        use_reloader=False
    )
