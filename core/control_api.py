from flask import Flask, jsonify
import threading


class ControlAPI:

    def __init__(self, firewall_control, block_engine, threat_db, threat_memory, reset_runtime_callback):
        self.firewall_control = firewall_control
        self.block_engine = block_engine
        self.threat_db = threat_db
        self.threat_memory = threat_memory
        self.reset_runtime_callback = reset_runtime_callback

        self.app = Flask(__name__)
        self._setup_routes()

    def _setup_routes(self):
        @self.app.route("/status", methods=["GET"])
        def status():
            return jsonify({
                "mode": self.firewall_control.get_mode(),
                "protection_enabled": self.firewall_control.is_protection_enabled(),
                "active_blocks": list(self.block_engine.active_blocks.keys()),
                "active_block_count": len(self.block_engine.active_blocks),
                "known_attackers": len(getattr(self.threat_memory, "db", {})),
                "threat_db_entries": len(getattr(self.threat_db, "threat_map", {}))
            })

        @self.app.route("/mode/detect", methods=["POST", "GET"])
        def set_detect():
            self.firewall_control.set_detect_mode()
            return jsonify({
                "status": "ok",
                "mode": self.firewall_control.get_mode()
            })

        @self.app.route("/mode/protect", methods=["POST", "GET"])
        def set_protect():
            self.firewall_control.set_protect_mode()
            return jsonify({
                "status": "ok",
                "mode": self.firewall_control.get_mode()
            })

        @self.app.route("/mode/toggle", methods=["POST", "GET"])
        def toggle():
            self.firewall_control.toggle_mode()
            return jsonify({
                "status": "ok",
                "mode": self.firewall_control.get_mode()
            })

        @self.app.route("/reset", methods=["POST", "GET"])
        def reset():
            try:
                self.reset_runtime_callback()
            except Exception as e:
                return jsonify({
                    "status": "error",
                    "message": f"Runtime reset failed: {e}"
                }), 500

            try:
                self.firewall_control.reset_memory_files()
            except Exception as e:
                return jsonify({
                    "status": "error",
                    "message": f"Persistent reset failed: {e}"
                }), 500

            return jsonify({
                "status": "ok",
                "message": "Firewall memory reset and all blocks cleared"
            })

    def start(self, host="0.0.0.0", port=7400):
        def runner():
            print(f"🎛️ Aegis Control API running on http://{host}:{port}")

            self.app.run(
                host=host,
                port=port,
                debug=False,
                use_reloader=False
            )

        threading.Thread(target=runner, daemon=True).start()
