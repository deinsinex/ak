from flask import Flask, request, jsonify
import time


app = Flask(__name__)


def client_ip():
    """
    Real packet source IP from Flask socket context.
    In namespace lab this should be the actual namespace IP.
    """
    return request.remote_addr


def log_request(label):
    print(
        f"[VULN-SERVER] {label} | "
        f"src={client_ip()} | "
        f"path={request.path} | "
        f"method={request.method} | "
        f"args={dict(request.args)}"
    )


@app.route("/")
def home():
    log_request("HOME")
    return "Aegis Vulnerable Test Server Running on port 7200"


@app.route("/login", methods=["GET", "POST"])
def login():
    log_request("LOGIN")

    username = request.args.get("user", "")
    password = request.args.get("pass", "")

    # Intentionally weak demo logic (safe for lab)
    if username == "admin" and password == "admin":
        return "Login success"

    return "Login failed"


@app.route("/admin", methods=["GET"])
def admin():
    log_request("ADMIN")

    token = request.args.get("token", "")

    if token == "letmein":
        return "Admin panel granted"

    return "Admin access denied", 403


@app.route("/status", methods=["GET"])
def status():
    log_request("STATUS")

    return jsonify({
        "server": "Aegis Vulnerable Test Server",
        "status": "running",
        "timestamp": int(time.time()),
        "source_ip": client_ip()
    })


@app.route("/api", methods=["GET", "POST"])
def api():
    log_request("API")

    action = request.args.get("action", "")

    return jsonify({
        "message": "API endpoint hit",
        "action": action,
        "source_ip": client_ip()
    })


@app.route("/cmd", methods=["GET"])
def cmd():
    log_request("CMD")

    command = request.args.get("cmd", "")

    if command:
        print(f"[VULN-SERVER] Simulated command received from {client_ip()}: {command}")

        # SAFE: simulate only, never execute
        return f"Simulated execution: {command}"

    return "No command"


@app.route("/upload", methods=["POST"])
def upload():
    log_request("UPLOAD")

    data = request.data

    preview = data[:200]

    print(f"[VULN-SERVER] Received payload from {client_ip()}: {preview}")

    return "Upload received"


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "port": 7200,
        "bind": "0.0.0.0"
    })


if __name__ == "__main__":

    print("⚠️ Starting Aegis Vulnerable Test Server on 0.0.0.0:7200")

    app.run(
        host="0.0.0.0",
        port=7200,
        debug=False,
        use_reloader=False
    )
