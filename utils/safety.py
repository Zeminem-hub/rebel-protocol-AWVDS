import ipaddress
import socket
from urllib.parse import urlparse

BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_safe_target(url: str) -> tuple[bool, str]:
    """Resolve the target hostname and reject private / loopback ranges."""
    hostname = urlparse(url).hostname
    if not hostname:
        return False, "URL has no hostname"
    if hostname.lower() in ("localhost", "localhost.localdomain"):
        return False, "Loopback hostnames are not allowed"
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        return False, f"DNS lookup failed: {e}"
    for info in infos:
        ip_str = info[4][0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        for net in BLOCKED_NETWORKS:
            if addr.version == net.version and addr in net:
                return False, f"Target resolves to private/loopback address {ip_str}"
    return True, ""
