import os
import json

class FirewallControl:

    def __init__(self):

        self.mode = "detect"

    def set_detect_mode(self):

        self.mode = "detect"

        print("Firewall switched to DETECTION mode")

    def set_protect_mode(self):

        self.mode = "protect"

        print("Firewall switched to PROTECTION mode")

    def is_protection_enabled(self):

        return self.mode == "protect"


    def reset_memory(self):

        print("Resetting firewall memory")

        files = [
            "logs/attacks.json",
            "intel/threat_reputation.json"
        ]

        for f in files:

            try:

                open(f,"w").close()

            except:
                pass

        print("Memory cleared")
