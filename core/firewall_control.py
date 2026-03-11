import os
import json


STATE_FILE = "core/firewall_state.json"


class FirewallControl:

    def __init__(self):
        self.mode = "detect"
        self._load_state()

    def _load_state(self):
        """
        Load persistent firewall mode from disk.
        Defaults safely to DETECT mode.
        """
        try:
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE, "r") as f:
                    data = json.load(f)

                mode = data.get("mode", "detect")

                if mode in ("detect", "protect"):
                    self.mode = mode
                else:
                    self.mode = "detect"

        except Exception as e:
            print(f"[FIREWALL CONTROL] Failed to load state: {e}")
            self.mode = "detect"

    def _save_state(self):
        """
        Persist firewall mode to disk.
        """
        try:
            os.makedirs("core", exist_ok=True)

            with open(STATE_FILE, "w") as f:
                json.dump({"mode": self.mode}, f, indent=4)

        except Exception as e:
            print(f"[FIREWALL CONTROL] Failed to save state: {e}")

    def set_detect_mode(self):
        self.mode = "detect"
        self._save_state()
        print("🟡 Firewall switched to DETECT mode")

    def set_protect_mode(self):
        self.mode = "protect"
        self._save_state()
        print("🟢 Firewall switched to PROTECT mode")

    def toggle_mode(self):
        if self.mode == "detect":
            self.set_protect_mode()
        else:
            self.set_detect_mode()

    def get_mode(self):
        return self.mode

    def is_protection_enabled(self):
        return self.mode == "protect"

    def reset_memory_files(self):
        """
        Clear persistent files only.
        Runtime in-memory objects must be reset separately in main.py.
        """
        print("🧹 Resetting persistent firewall memory...")

        reset_targets = [
            ("logs/attacks.json", ""),
            ("intel/threat_reputation.json", "{}"),
            ("federation/threat_feed.json", "[]"),
            ("federation/local_model.json", "{}"),
            ("federation/local_model_version.txt", "0")
        ]

        for file_path, default_content in reset_targets:
            try:
                directory = os.path.dirname(file_path)
                if directory:
                    os.makedirs(directory, exist_ok=True)

                with open(file_path, "w") as f:
                    f.write(default_content)

                print(f"[RESET] Cleared {file_path}")

            except Exception as e:
                print(f"[RESET] Failed to clear {file_path}: {e}")

        print("✅ Persistent memory cleared")
