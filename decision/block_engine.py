import subprocess
import threading
import time


class BlockEngine:

    def __init__(self):

        self.active_blocks = {}

    def block_ip(self, ip, duration=300):

        if ip in self.active_blocks:
            return

        print(f"\n🔥 Blocking {ip} for {duration} seconds")

        try:

            subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True
            )

            expiry = time.time() + duration
            self.active_blocks[ip] = expiry

            threading.Thread(
                target=self._unblock_after_timeout,
                args=(ip, duration),
                daemon=True
            ).start()

        except subprocess.CalledProcessError as e:

            print("❌ Failed to apply iptables rule:", e)

    def _unblock_after_timeout(self, ip, duration):

        time.sleep(duration)

        print(f"\n🔓 Unblocking {ip}")

        try:

            subprocess.run(
                ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True
            )

        except subprocess.CalledProcessError:

            print("⚠️ Rule removal failed (possibly already removed)")

        if ip in self.active_blocks:
            del self.active_blocks[ip]
