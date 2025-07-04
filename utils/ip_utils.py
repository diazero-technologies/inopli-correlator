import ipaddress

def is_public_ip(ip: str) -> bool:
    """
    Returns True if the IP address is public (not private, loopback, link-local, or reserved).
    Returns False for private, loopback, link-local, or reserved IPs.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_global
    except ValueError:
        return False 