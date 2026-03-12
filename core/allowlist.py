import ipaddress
import socket


class AllowlistManager:
    def __init__(self):
        self.exact_ips = set(["127.0.0.1", "::1"])
        self.cidr_ranges = [
            ipaddress.ip_network("127.0.0.0/8", strict=False),
            ipaddress.ip_network("10.0.0.0/8", strict=False),
            ipaddress.ip_network("172.16.0.0/12", strict=False),
            ipaddress.ip_network("192.168.0.0/16", strict=False),
            ipaddress.ip_network("169.254.0.0/16", strict=False),
        ]

    def add_ip(self, ip: str):
        if ip:
            self.exact_ips.add(ip)

    def add_cidr(self, cidr: str):
        try:
            self.cidr_ranges.append(ipaddress.ip_network(cidr, strict=False))
        except Exception:
            pass

    def is_allowlisted(self, ip: str) -> bool:
        if not ip:
            return True

        if ip in self.exact_ips:
            return True

        try:
            ip_obj = ipaddress.ip_address(ip)
        except Exception:
            return True  # invalid IP -> don't punish

        if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_multicast:
            return True

        for net in self.cidr_ranges:
            if ip_obj in net:
                return True

        return False

    def is_safe_outbound_service(self, dst_ip: str, dst_port: int | None) -> bool:
        """
        Very conservative safe-outbound rule:
        normal client web/DNS traffic should not be treated like scanning.
        """
        if self.is_allowlisted(dst_ip):
            return True

        if dst_port in {53, 80, 443, 123}:
            return True

        return False

    def summary(self):
        return {
            "exact_ip_count": len(self.exact_ips),
            "cidr_count": len(self.cidr_ranges),
            "entries": {
                "exact_ips": sorted(list(self.exact_ips)),
                "cidr_ranges": [str(x) for x in self.cidr_ranges],
            },
        }


def get_local_ips():
    ips = set(["127.0.0.1", "::1"])
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            ips.add(ip)
    except Exception:
        pass
    return ips
