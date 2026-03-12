from flask import Flask, jsonify

app = Flask(__name__)

# These will be injected from main.py
runtime = {
    "firewall_control": None,
    "block_engine": None,
    "allowlist_engine": None,
    "reset_callback": None,
    "status_callback": None
}


# =========================================================
# RUNTIME REGISTRATION
# =========================================================

def register_runtime(
    firewall_control,
    block_engine,
    allowlist_engine,
    reset_callback,
    status_callback
):
    runtime["firewall_control"] = firewall_control
    runtime["block_engine"] = block_engine
    runtime["allowlist_engine"] = allowlist_engine
    runtime["reset_callback"] = reset_callback
    runtime["status_callback"] = status_callback

    print("✅ Control API runtime registered")


# =========================================================
# ROUTES
# =========================================================

@app.route("/")
def home():
    return jsonify({
        "service": "Aegis Control API",
        "routes": [
            "/status",
            "/mode/detect",
            "/mode/protect",
            "/mode/toggle",
            "/reset",
            "/unblock_all",
            "/allowlist/reload",
            "/allowlist/summary"
        ]
    })


@app.route("/status")
def status():
    try:
        cb = runtime.get("status_callback")

        if cb is None:
            return jsonify({
                "status": "error",
                "message": "Runtime not registered"
            }), 500

        return jsonify(cb())

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/mode/detect")
def set_detect_mode():
    try:
        fw = runtime.get("firewall_control")

        if fw is None:
            return jsonify({
                "status": "error",
                "message": "FirewallControl not registered"
            }), 500

        fw.set_detect_mode()

        return jsonify({
            "status": "ok",
            "mode": fw.get_mode(),
            "message": "Firewall switched to DETECT mode"
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/mode/protect")
def set_protect_mode():
    try:
        fw = runtime.get("firewall_control")

        if fw is None:
            return jsonify({
                "status": "error",
                "message": "FirewallControl not registered"
            }), 500

        fw.set_protect_mode()

        return jsonify({
            "status": "ok",
            "mode": fw.get_mode(),
            "message": "Firewall switched to PROTECT mode"
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/mode/toggle")
def toggle_mode():
    try:
        fw = runtime.get("firewall_control")

        if fw is None:
            return jsonify({
                "status": "error",
                "message": "FirewallControl not registered"
            }), 500

        fw.toggle_mode()

        return jsonify({
            "status": "ok",
            "mode": fw.get_mode(),
            "message": f"Firewall mode toggled to {fw.get_mode()}"
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/reset")
def reset():
    try:
        cb = runtime.get("reset_callback")

        if cb is None:
            return jsonify({
                "status": "error",
                "message": "Reset callback not registered"
            }), 500

        cb()

        return jsonify({
            "status": "ok",
            "message": "Firewall runtime + persistent memory reset completed"
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/unblock_all")
def unblock_all():
    try:
        be = runtime.get("block_engine")

        if be is None:
            return jsonify({
                "status": "error",
                "message": "BlockEngine not registered"
            }), 500

        be.unblock_all()

        return jsonify({
            "status": "ok",
            "message": "All active firewall blocks removed"
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/allowlist/reload")
def reload_allowlist():
    try:
        ae = runtime.get("allowlist_engine")

        if ae is None:
            return jsonify({
                "status": "error",
                "message": "AllowlistEngine not registered"
            }), 500

        ae.reload()

        return jsonify({
            "status": "ok",
            "message": "Allowlist reloaded",
            "summary": ae.summary()
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/allowlist/summary")
def allowlist_summary():
    try:
        ae = runtime.get("allowlist_engine")

        if ae is None:
            return jsonify({
                "status": "error",
                "message": "AllowlistEngine not registered"
            }), 500

        return jsonify({
            "status": "ok",
            "summary": ae.summary()
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# =========================================================
# STARTER
# =========================================================

def start_control_api():
    print("🎛️ Aegis Control API running on port 7400")

    app.run(
        host="0.0.0.0",
        port=7400,
        debug=False,
        use_reloader=False
    )


if __name__ == "__main__":
    print("⚠️ This file should be started from main.py after runtime registration.")
    start_control_api()
