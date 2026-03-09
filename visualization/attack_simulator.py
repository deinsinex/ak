import subprocess


def run_port_scan():

    print("[SIM] Running port scan attack")

    subprocess.Popen(
        ["sudo", "nmap", "-sS", "127.0.0.1"]
    )


def run_stealth_scan():

    print("[SIM] Running stealth scan")

    subprocess.Popen(
        ["sudo", "nmap", "-sN", "127.0.0.1"]
    )


def run_payload_attack():

    print("[SIM] Sending payload attack")

    subprocess.Popen(
        [
            "curl",
            "http://127.0.0.1:5001/cmd?cmd=bash+-i"
        ]
    )


def run_multi_stage_attack():

    print("[SIM] Running multi-stage attack")

    subprocess.Popen(
        ["sudo", "nmap", "-sS", "127.0.0.1"]
    )

    subprocess.Popen(
        [
            "curl",
            "http://127.0.0.1:5001/cmd?cmd=chmod+777"
        ]
    )
