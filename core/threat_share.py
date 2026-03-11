import requests
import urllib3


# Local collaborative threat intel server
THREAT_FEED_URL = "https://localhost:8100/threat_feed"
REPORT_URL = "https://localhost:8100/report_threat"

# Disable SSL warnings for self-signed local lab cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def fetch_threat_feed():
    """
    Fetch collaborative threat intelligence feed from the local federation server.

    Returns:
        dict: { "blocked_ips": [...], "reported_threats": [...] }
    """
    try:
        response = requests.get(
            THREAT_FEED_URL,
            verify=False,
            timeout=5
        )

        if response.status_code != 200:
            print(f"[THREAT SHARE] Feed fetch failed: HTTP {response.status_code}")
            return {
                "blocked_ips": [],
                "reported_threats": []
            }

        data = response.json()

        if not isinstance(data, dict):
            print("[THREAT SHARE] Invalid feed format received.")
            return {
                "blocked_ips": [],
                "reported_threats": []
            }

        blocked_ips = data.get("blocked_ips", [])
        reported_threats = data.get("reported_threats", [])

        if not isinstance(blocked_ips, list):
            blocked_ips = []

        if not isinstance(reported_threats, list):
            reported_threats = []

        return {
            "blocked_ips": blocked_ips,
            "reported_threats": reported_threats
        }

    except requests.exceptions.RequestException as e:
        print(f"[THREAT SHARE] Feed unavailable: {e}")
        return {
            "blocked_ips": [],
            "reported_threats": []
        }


def share_threat(ip, reason):
    """
    Report a detected malicious IP to the collaborative threat intel server.

    Args:
        ip (str): Suspicious or malicious IP
        reason (str): Why it was reported
    """
    payload = {
        "ip": ip,
        "reason": reason
    }

    try:
        response = requests.post(
            REPORT_URL,
            json=payload,
            verify=False,
            timeout=5
        )

        if response.status_code == 200:
            print(f"[THREAT SHARE] Shared threat: {ip} ({reason})")
        else:
            print(f"[THREAT SHARE] Share failed: HTTP {response.status_code}")

    except requests.exceptions.RequestException as e:
        print(f"[THREAT SHARE] Could not share threat: {e}")
