import subprocess
import time


BRIDGE_NAME = "aegis-br0"
BRIDGE_IP = "10.200.1.1/24"

NAMESPACES = [
    ("bot1", "10.200.1.11/24"),
    ("bot2", "10.200.1.12/24"),
    ("bot3", "10.200.1.13/24"),
    ("bot4", "10.200.1.14/24"),
]

TARGET_IP = "10.200.1.1"
TARGET_PORT = 7200


def run(cmd, check=False):
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\n"
            f"STDOUT: {result.stdout}\n"
            f"STDERR: {result.stderr}"
        )

    return result


# =========================================================
# HELPERS
# =========================================================

def ns_exists(name):
    result = run(["sudo", "ip", "netns", "list"])
    return name in result.stdout


def iface_exists(name):
    result = run(["ip", "link", "show", name])
    return result.returncode == 0


def bridge_exists():
    return iface_exists(BRIDGE_NAME)


def get_namespace_ips():
    return [ip.split("/")[0] for _, ip in NAMESPACES]


# =========================================================
# LAB SETUP
# =========================================================

def setup_lab():
    print("\n🧪 Setting up Aegis multi-IP namespace lab...")

    # Create bridge if missing
    if not bridge_exists():
        run(["sudo", "ip", "link", "add", BRIDGE_NAME, "type", "bridge"], check=True)
        print(f"🛠️ Created bridge {BRIDGE_NAME}")

    # Assign bridge IP (ignore if already set)
    run(["sudo", "ip", "addr", "add", BRIDGE_IP, "dev", BRIDGE_NAME], check=False)

    # Bring bridge up
    run(["sudo", "ip", "link", "set", BRIDGE_NAME, "up"], check=True)

    # Create namespaces + veth pairs
    for index, (ns_name, ns_ip) in enumerate(NAMESPACES, start=1):
        host_veth = f"veth{index}h"
        ns_veth = f"veth{index}n"

        if not ns_exists(ns_name):
            run(["sudo", "ip", "netns", "add", ns_name], check=True)
            print(f"📦 Created namespace {ns_name}")

        if not iface_exists(host_veth):
            run(
                ["sudo", "ip", "link", "add", host_veth, "type", "veth", "peer", "name", ns_veth],
                check=True
            )
            print(f"🔌 Created veth pair {host_veth} <-> {ns_veth}")

        # Move namespace side into namespace (ignore if already moved)
        run(["sudo", "ip", "link", "set", ns_veth, "netns", ns_name], check=False)

        # Attach host side to bridge
        run(["sudo", "ip", "link", "set", host_veth, "master", BRIDGE_NAME], check=False)
        run(["sudo", "ip", "link", "set", host_veth, "up"], check=False)

        # Bring loopback up in namespace
        run(["sudo", "ip", "netns", "exec", ns_name, "ip", "link", "set", "lo", "up"], check=False)

        # Assign namespace IP
        run(["sudo", "ip", "netns", "exec", ns_name, "ip", "addr", "add", ns_ip, "dev", ns_veth], check=False)

        # Bring namespace veth up
        run(["sudo", "ip", "netns", "exec", ns_name, "ip", "link", "set", ns_veth, "up"], check=False)

        # Add route to bridge target
        run(
            ["sudo", "ip", "netns", "exec", ns_name, "ip", "route", "add", "default", "via", TARGET_IP],
            check=False
        )

    print("✅ Namespace lab ready")
    print(f"🎯 Target test server expected at http://{TARGET_IP}:{TARGET_PORT}")


# =========================================================
# LAB STATUS
# =========================================================

def lab_status():
    status = {
        "bridge": BRIDGE_NAME,
        "bridge_exists": bridge_exists(),
        "target_ip": TARGET_IP,
        "target_port": TARGET_PORT,
        "namespaces": []
    }

    for ns_name, ns_ip in NAMESPACES:
        status["namespaces"].append({
            "name": ns_name,
            "ip": ns_ip,
            "exists": ns_exists(ns_name)
        })

    return status


# =========================================================
# ATTACK FUNCTIONS
# =========================================================

def http_burst(ns_name, count=30):
    """
    Send multiple HTTP requests from one namespace.
    """
    print(f"🌐 HTTP burst from {ns_name}")

    for _ in range(count):
        run(
            [
                "sudo", "ip", "netns", "exec", ns_name,
                "curl", "-s",
                f"http://{TARGET_IP}:{TARGET_PORT}/"
            ],
            check=False
        )


def payload_attack(ns_name):
    """
    Simulate suspicious command payload.
    """
    print(f"💣 Payload attack from {ns_name}")

    run(
        [
            "sudo", "ip", "netns", "exec", ns_name,
            "curl", "-s",
            f"http://{TARGET_IP}:{TARGET_PORT}/cmd?cmd=nc%20-e%20/bin/sh"
        ],
        check=False
    )


def login_bruteforce(ns_name, attempts=20):
    """
    Simulate repeated login attempts.
    """
    print(f"🔐 Login brute-force from {ns_name}")

    for i in range(attempts):
        run(
            [
                "sudo", "ip", "netns", "exec", ns_name,
                "curl", "-s",
                f"http://{TARGET_IP}:{TARGET_PORT}/login?user=admin&pass=wrong{i}"
            ],
            check=False
        )


def port_scan(ns_name):
    """
    Run an nmap scan from one namespace.
    """
    print(f"🛰️ Port scan from {ns_name}")

    run(
        [
            "sudo", "ip", "netns", "exec", ns_name,
            "nmap", "-Pn", "-p", "1-1000", TARGET_IP
        ],
        check=False
    )


def syn_burst(ns_name, count=50):
    """
    Controlled SYN burst (not endless flood).
    Safer than --flood.
    """
    print(f"⚡ SYN burst from {ns_name}")

    run(
        [
            "sudo", "ip", "netns", "exec", ns_name,
            "hping3", "-S", "-p", str(TARGET_PORT), "-c", str(count), TARGET_IP
        ],
        check=False
    )


def mixed_attack_all():
    """
    Launch mixed attacks from all namespaces.
    """
    print("\n🔥 Starting multi-IP mixed botnet attack...\n")

    for ns_name, _ in NAMESPACES:
        port_scan(ns_name)
        time.sleep(0.5)

    for ns_name, _ in NAMESPACES:
        login_bruteforce(ns_name, attempts=10)
        time.sleep(0.3)

    for ns_name, _ in NAMESPACES:
        payload_attack(ns_name)
        time.sleep(0.3)

    for ns_name, _ in NAMESPACES:
        http_burst(ns_name, count=20)
        time.sleep(0.2)

    for ns_name, _ in NAMESPACES:
        syn_burst(ns_name, count=20)
        time.sleep(0.2)

    print("\n✅ Multi-IP mixed attack completed")


# =========================================================
# LAB DESTROY
# =========================================================

def destroy_lab():
    print("\n🧹 Destroying Aegis namespace lab...")

    # Delete namespaces
    for ns_name, _ in NAMESPACES:
        if ns_exists(ns_name):
            run(["sudo", "ip", "netns", "del", ns_name], check=False)
            print(f"🗑️ Removed namespace {ns_name}")

    # Delete bridge
    if bridge_exists():
        run(["sudo", "ip", "link", "set", BRIDGE_NAME, "down"], check=False)
        run(["sudo", "ip", "link", "del", BRIDGE_NAME], check=False)
        print(f"🗑️ Removed bridge {BRIDGE_NAME}")

    print("✅ Namespace lab destroyed")
