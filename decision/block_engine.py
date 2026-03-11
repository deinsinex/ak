import subprocess
import threading
import time


class BlockEngine:

    def __init__(self):
        self.active_blocks = {}
        self.chain_name = "AEGIS_BLOCK"

        self._ensure_chain()

    def _run(self, cmd, check=False):
        """
        Internal helper to run sudo iptables commands safely.
        Only BlockEngine uses sudo internally.
        """
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

    def _ensure_chain(self):
        """
        Ensure dedicated AEGIS_BLOCK chain exists and is linked from INPUT.
        """
        try:
            # Create chain if missing
            result = self._run(
                ["sudo", "iptables", "-L", self.chain_name],
                check=False
            )

            if result.returncode != 0:
                self._run(
                    ["sudo", "iptables", "-N", self.chain_name],
                    check=False
                )
                print(f"🧱 Created iptables chain: {self.chain_name}")

            # Ensure INPUT jumps to AEGIS_BLOCK
            check_jump = self._run(
                ["sudo", "iptables", "-C", "INPUT", "-j", self.chain_name],
                check=False
            )

            if check_jump.returncode != 0:
                self._run(
                    ["sudo", "iptables", "-I", "INPUT", "1", "-j", self.chain_name],
                    check=False
                )
                print(f"🔗 Linked INPUT -> {self.chain_name}")

        except Exception as e:
            print("❌ Failed to ensure AEGIS_BLOCK chain:", e)

    def _rule_exists(self, ip):
        """
        Check if a DROP rule for this IP already exists in AEGIS_BLOCK.
        """
        result = self._run(
            ["sudo", "iptables", "-C", self.chain_name, "-s", ip, "-j", "DROP"],
            check=False
        )

        return result.returncode == 0

    def block_ip(self, ip, duration=300):
        """
        Block a source IP for a duration.
        Returns True if block was applied, False if skipped/failed.
        """
        self._ensure_chain()

        if ip in self.active_blocks:
            print(f"⚠️ {ip} is already actively blocked")
            return False

        if self._rule_exists(ip):
            print(f"⚠️ iptables rule already exists for {ip}, syncing runtime state")
            expiry = time.time() + duration
            self.active_blocks[ip] = expiry

            threading.Thread(
                target=self._unblock_after_timeout,
                args=(ip, duration),
                daemon=True
            ).start()

            return True

        print(f"\n🔥 Blocking {ip} for {duration} seconds")

        try:
            result = self._run(
                ["sudo", "iptables", "-A", self.chain_name, "-s", ip, "-j", "DROP"],
                check=False
            )

            if result.returncode != 0:
                print("❌ Failed to apply iptables rule")
                print(result.stderr.strip())
                return False

            expiry = time.time() + duration
            self.active_blocks[ip] = expiry

            threading.Thread(
                target=self._unblock_after_timeout,
                args=(ip, duration),
                daemon=True
            ).start()

            return True

        except Exception as e:
            print("❌ Block error:", e)
            return False

    def unblock_ip(self, ip):
        """
        Remove block for a single IP if present.
        """
        self._ensure_chain()

        print(f"\n🔓 Unblocking {ip}")

        try:
            # Remove all matching rules just in case duplicates somehow exist
            while self._rule_exists(ip):
                self._run(
                    ["sudo", "iptables", "-D", self.chain_name, "-s", ip, "-j", "DROP"],
                    check=False
                )

            if ip in self.active_blocks:
                del self.active_blocks[ip]

            return True

        except Exception as e:
            print(f"⚠️ Failed to unblock {ip}: {e}")
            return False

    def _unblock_after_timeout(self, ip, duration):
        """
        Auto-unblock after timeout.
        """
        time.sleep(duration)

        # If IP already manually unblocked, just exit
        if ip not in self.active_blocks:
            return

        self.unblock_ip(ip)

    def unblock_all(self):
        """
        Remove all Aegis-managed IP block rules and clear runtime state.
        Safe: only touches AEGIS_BLOCK chain, not full firewall.
        """
        self._ensure_chain()

        print("\n🧹 Unblocking ALL Aegis-managed IPs")

        try:
            # Flush only our dedicated chain
            self._run(
                ["sudo", "iptables", "-F", self.chain_name],
                check=False
            )

            self.active_blocks.clear()

            print("✅ All Aegis blocks cleared")
            return True

        except Exception as e:
            print("❌ Failed to clear Aegis blocks:", e)
            return False

    def status(self):
        """
        Return runtime status.
        """
        now = time.time()

        status = {}

        for ip, expiry in self.active_blocks.items():
            remaining = max(0, int(expiry - now))
            status[ip] = {
                "expires_in_seconds": remaining
            }

        return status

    def destroy_chain(self):
        """
        Optional cleanup: remove jump and delete AEGIS_BLOCK chain.
        Use only if you want full teardown.
        """
        print(f"\n🗑️ Destroying chain {self.chain_name}")

        try:
            # Flush chain first
            self._run(
                ["sudo", "iptables", "-F", self.chain_name],
                check=False
            )

            # Remove INPUT jump if exists
            while True:
                check_jump = self._run(
                    ["sudo", "iptables", "-C", "INPUT", "-j", self.chain_name],
                    check=False
                )

                if check_jump.returncode != 0:
                    break

                self._run(
                    ["sudo", "iptables", "-D", "INPUT", "-j", self.chain_name],
                    check=False
                )

            # Delete chain
            self._run(
                ["sudo", "iptables", "-X", self.chain_name],
                check=False
            )

            self.active_blocks.clear()

            print(f"✅ Chain {self.chain_name} destroyed")
            return True

        except Exception as e:
            print(f"❌ Failed to destroy chain {self.chain_name}: {e}")
            return False
