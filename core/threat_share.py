import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INTEL_SERVER = "http://localhost:8200"


def share_threat(ip, reason):

    try:

        payload = {
            "ip": ip,
            "reason": reason
        }

        requests.post(
            f"{INTEL_SERVER}/submit_intel",
            json=payload,
            timeout=3
        )

    except Exception as e:

        print("Threat share failed:", e)


def fetch_threat_feed():

    try:

        r = requests.get(
            f"{INTEL_SERVER}/get_intel",
            timeout=5
        )

        return r.json()

    except Exception:

        return {}
