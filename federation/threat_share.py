import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

THREAT_FEED_URL = "http://127.0.0.1:8200/share"


def share_threat_event(ip, event_name):
    """
    Share a threat event to collaborative intel server.
    Safe no-op if server is unavailable.
    """
    payload = {
        "ip": ip,
        "event": event_name
    }

    try:
        response = requests.post(
            THREAT_FEED_URL,
            json=payload,
            timeout=3
        )

        if response.status_code == 200:
            print(f"[THREAT SHARE] Shared {event_name} for {ip}")
        else:
            print(f"[THREAT SHARE] Server returned {response.status_code}")

    except Exception as e:
        print(f"[THREAT SHARE] Share skipped: {e}")
