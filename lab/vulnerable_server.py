from flask import Flask, request

app = Flask(__name__)


@app.route("/")
def home():
    return "Aegis Test Server Running"


@app.route("/login", methods=["GET","POST"])
def login():

    username = request.args.get("user")
    password = request.args.get("pass")

    if username == "admin" and password == "admin":

        return "Login success"

    return "Login failed"


@app.route("/cmd")
def cmd():

    command = request.args.get("cmd")

    if command:

        print("[SERVER] Command received:", command)

        return f"Executed command: {command}"

    return "No command"


@app.route("/upload", methods=["POST"])
def upload():

    data = request.data

    print("[SERVER] Received payload:", data)

    return "Upload received"


if __name__ == "__main__":

    print("Starting vulnerable test server on port 5001")

    app.run(
        host="0.0.0.0",
        port=5001
    )
