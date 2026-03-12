import os
import json
import ipaddress


ALLOWLIST_FILE = "core/allowlist.json"


class AllowlistEngine:

    def __init__(self, allowlist_file=ALLOWLIST_FILE):
        self.allowlist_file = allowlist_file
        self.exact_ips = set()
        self.networks = []
        self._ensure_default_file()
        self.reload()

    # ==========================================
    # FILE MANAGEMENT
    # ==========================================

    def _ensure_default_file(self):
        """
        Create a safe default allowlist if missing.
        """
        if os.path.exists(self.allowlist_file):
            return

        os.makedirs(os.path.dirname(self.allowlist_file), exist_ok=True)

        default_data = {
            "exact_ips": [
                "127.0.0.1",
                "::1"
            ],
            "cidr_ranges": [
                "127.0.0.0/8"
            ],
            "notes": [
                "Add only infrastructure IPs you NEVER want blocked.",
                "Do NOT add attacker lab subnets here if you want real multi-IP blocking."
            ]
        }

        with open(self.allowlist_file, "w") as f:
            json.dump(default_data, f, indent=4)

        print(f"[ALLOWLIST] Created default allowlist at {self.allowlist_file}")

    def reload(self):
        """
        Reload allowlist from disk safely.
        """
        self.exact_ips = set()
        self.networks = []

        try:
            if not os.path.exists(self.allowlist_file):
                self._ensure_default_file()

            if os.path.getsize(self.allowlist_file) == 0:
                print("[ALLOWLIST] File empty, using defaults")
                self._ensure_default_file()

            with open(self.allowlist_file, "r") as f:
                data = json.load(f)

            exact_ips = data.get("exact_ips", [])
            cidr_ranges = data.get("cidr_ranges", [])

            for ip in exact_ips:
                try:
                    # validate IP
                    ipaddress.ip_address(ip)
                    self.exact_ips.add(ip)
                except Exception:
                    print(f"[ALLOWLIST] Skipping invalid IP: {ip}")

            for cidr in cidr_ranges:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    self.networks.append(net)
                except Exception:
                    print(f"[ALLOWLIST] Skipping invalid CIDR: {cidr}")

            print(f"[ALLOWLIST] Loaded {len(self.exact_ips)} exact IP(s), {len(self.networks)} network(s)")

        except Exception as e:
            print(f"[ALLOWLIST] Failed to load allowlist: {e}")

    # ==========================================
    # LOOKUP
    # ==========================================

    def is_allowlisted(self, ip):
        if not ip:
            return True

        # exact match
        if ip in self.exact_ips:
            return True

        # CIDR match
        try:
            ip_obj = ipaddress.ip_address(ip)

            for net in self.networks:
                if ip_obj in net:
                    return True

        except Exception:
            pass

        return False

    # ==========================================
    # RUNTIME MODIFICATION
    # ==========================================

    def _read_raw(self):
        try:
            if not os.path.exists(self.allowlist_file):
                self._ensure_default_file()

            with open(self.allowlist_file, "r") as f:
                return json.load(f)

        except Exception:
            return {
                "exact_ips": [],
                "cidr_ranges": [],
                "notes": []
            }

    def _write_raw(self, data):
        os.makedirs(os.path.dirname(self.allowlist_file), exist_ok=True)

        with open(self.allowlist_file, "w") as f:
            json.dump(data, f, indent=4)

        self.reload()

    def add_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
        except Exception:
            print(f"[ALLOWLIST] Invalid IP not added: {ip}")
            return False

        data = self._read_raw()
        exact_ips = data.get("exact_ips", [])

        if ip not in exact_ips:
            exact_ips.append(ip)

        data["exact_ips"] = exact_ips
        self._write_raw(data)

        print(f"[ALLOWLIST] Added IP: {ip}")
        return True

    def remove_ip(self, ip):
        data = self._read_raw()
        exact_ips = data.get("exact_ips", [])

        if ip in exact_ips:
            exact_ips.remove(ip)

        data["exact_ips"] = exact_ips
        self._write_raw(data)

        print(f"[ALLOWLIST] Removed IP: {ip}")
        return True

    def add_cidr(self, cidr):
        try:
            ipaddress.ip_network(cidr, strict=False)
        except Exception:
            print(f"[ALLOWLIST] Invalid CIDR not added: {cidr}")
            return False

        data = self._read_raw()
        cidr_ranges = data.get("cidr_ranges", [])

        if cidr not in cidr_ranges:
            cidr_ranges.append(cidr)

        data["cidr_ranges"] = cidr_ranges
        self._write_raw(data)

        print(f"[ALLOWLIST] Added CIDR: {cidr}")
        return True

    def remove_cidr(self, cidr):
        data = self._read_raw()
        cidr_ranges = data.get("cidr_ranges", [])

        if cidr in cidr_ranges:
            cidr_ranges.remove(cidr)

        data["cidr_ranges"] = cidr_ranges
        self._write_raw(data)

        print(f"[ALLOWLIST] Removed CIDR: {cidr}")
        return True

    # ==========================================
    # INSPECTION
    # ==========================================

    def get_all(self):
        return {
            "exact_ips": sorted(list(self.exact_ips)),
            "cidr_ranges": [str(n) for n in self.networks]
        }

    def summary(self):
        return {
            "exact_ip_count": len(self.exact_ips),
            "cidr_count": len(self.networks),
            "entries": self.get_all()
        }
