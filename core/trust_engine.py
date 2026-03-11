import time
import os
import json
import ipaddress


TRUST_FILE = "core/trusted_networks.json"


class TrustEngine:

    def __init__(self):
        self.trust_scores = {}
        self.last_seen = {}

        self.MAX_TRUST = 100
        self.MIN_TRUST = 0

        self.trusted_ips = set()
        self.trusted_subnets = []

        self._load_or_initialize_trust_config()

    # ==========================================
    # TRUST SCORE SYSTEM
    # ==========================================

    def get_trust(self, ip):
        return self.trust_scores.get(ip, 50)

    def record_benign(self, ip):
        score = self.trust_scores.get(ip, 50)

        score += 1
        if score > self.MAX_TRUST:
            score = self.MAX_TRUST

        self.trust_scores[ip] = score
        self.last_seen[ip] = time.time()

    def record_suspicious(self, ip):
        score = self.trust_scores.get(ip, 50)

        score -= 10
        if score < self.MIN_TRUST:
            score = self.MIN_TRUST

        self.trust_scores[ip] = score
        self.last_seen[ip] = time.time()

    def record_attack(self, ip):
        score = self.trust_scores.get(ip, 50)

        score -= 30
        if score < self.MIN_TRUST:
            score = self.MIN_TRUST

        self.trust_scores[ip] = score
        self.last_seen[ip] = time.time()

    def is_untrusted(self, ip):
        score = self.get_trust(ip)
        return score < 20

    def observe(self, ip):
        """
        Safe lightweight runtime observation.
        Keeps timestamps updated without changing trust score.
        """
        self.last_seen[ip] = time.time()

    # ==========================================
    # ALLOWLIST / TRUSTED NETWORK SYSTEM
    # ==========================================

    def _default_config(self):
        """
        IMPORTANT:
        Do NOT trust the entire 10.200.0.0/16 subnet because
        attacker namespaces use 10.200.x.2 in the real lab.
        Only trust infrastructure IPs explicitly.
        """
        return {
            "trusted_ips": [
                "127.0.0.1",
                "::1",
                "10.200.1.1",
                "10.200.2.1",
                "10.200.3.1"
            ],
            "trusted_subnets": [
                "127.0.0.0/8"
            ]
        }

    def _load_or_initialize_trust_config(self):
        try:
            if not os.path.exists(TRUST_FILE):
                self._save_config(self._default_config())

            with open(TRUST_FILE, "r") as f:
                data = json.load(f)

            trusted_ips = data.get("trusted_ips", [])
            trusted_subnets = data.get("trusted_subnets", [])

            self.trusted_ips = set()
            self.trusted_subnets = []

            for ip in trusted_ips:
                try:
                    ipaddress.ip_address(ip)
                    self.trusted_ips.add(ip)
                except Exception:
                    print(f"[TRUST] Invalid trusted IP ignored: {ip}")

            for cidr in trusted_subnets:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    self.trusted_subnets.append(net)
                except Exception:
                    print(f"[TRUST] Invalid trusted subnet ignored: {cidr}")

            print(f"[TRUST] Loaded {len(self.trusted_ips)} trusted IPs and {len(self.trusted_subnets)} trusted subnets")

        except Exception as e:
            print(f"[TRUST] Failed to load trust config: {e}")
            self.trusted_ips = set(self._default_config()["trusted_ips"])
            self.trusted_subnets = [
                ipaddress.ip_network(c, strict=False)
                for c in self._default_config()["trusted_subnets"]
            ]

    def _save_current_config(self):
        data = {
            "trusted_ips": sorted(list(self.trusted_ips)),
            "trusted_subnets": [str(n) for n in self.trusted_subnets]
        }
        self._save_config(data)

    def _save_config(self, data):
        try:
            os.makedirs("core", exist_ok=True)

            with open(TRUST_FILE, "w") as f:
                json.dump(data, f, indent=4)

        except Exception as e:
            print(f"[TRUST] Failed to save trust config: {e}")

    def is_trusted(self, ip):
        if not ip:
            return False

        if ip in self.trusted_ips:
            return True

        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return False

        for subnet in self.trusted_subnets:
            if addr in subnet:
                return True

        return False

    def add_trusted_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            self.trusted_ips.add(ip)
            self._save_current_config()
            print(f"[TRUST] Added trusted IP: {ip}")
            return True
        except Exception as e:
            print(f"[TRUST] Failed to add trusted IP {ip}: {e}")
            return False

    def remove_trusted_ip(self, ip):
        if ip in self.trusted_ips:
            self.trusted_ips.remove(ip)
            self._save_current_config()
            print(f"[TRUST] Removed trusted IP: {ip}")
            return True

        print(f"[TRUST] Trusted IP not found: {ip}")
        return False

    def add_trusted_subnet(self, cidr):
        try:
            net = ipaddress.ip_network(cidr, strict=False)

            if all(str(existing) != str(net) for existing in self.trusted_subnets):
                self.trusted_subnets.append(net)
                self._save_current_config()
                print(f"[TRUST] Added trusted subnet: {cidr}")

            return True

        except Exception as e:
            print(f"[TRUST] Failed to add trusted subnet {cidr}: {e}")
            return False

    def remove_trusted_subnet(self, cidr):
        removed = False

        try:
            target = str(ipaddress.ip_network(cidr, strict=False))

            new_subnets = []

            for net in self.trusted_subnets:
                if str(net) == target:
                    removed = True
                else:
                    new_subnets.append(net)

            self.trusted_subnets = new_subnets

            if removed:
                self._save_current_config()
                print(f"[TRUST] Removed trusted subnet: {cidr}")
            else:
                print(f"[TRUST] Trusted subnet not found: {cidr}")

            return removed

        except Exception as e:
            print(f"[TRUST] Failed to remove trusted subnet {cidr}: {e}")
            return False

    def list_trusted(self):
        return {
            "trusted_ips": sorted(list(self.trusted_ips)),
            "trusted_subnets": [str(n) for n in self.trusted_subnets]
        }
