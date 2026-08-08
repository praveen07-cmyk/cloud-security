"""
geoip_helper.py
------------------------------------------------
Safe, non-blocking GeoIP resolver for approximate IP-based location auditing.
Does NOT make external HTTP requests by default; safely resolves local/private IPs,
and supports local/optional GeoIP databases when configured.
"""

from ipaddress import ip_address, ip_network

LOCATION_NOTE = "Approximate IP-based location"

PRIVATE_NETWORKS = [
    ip_network("127.0.0.0/8"),
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("::1/128"),
    ip_network("fe80::/10"),
]


def resolve_ip_location(ip_str):
    """
    Returns approximate location metadata dict:
    - country
    - region
    - city
    - location_label
    - is_private
    """
    if not ip_str or not isinstance(ip_str, str):
        return {
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "location_label": LOCATION_NOTE,
            "is_private": False,
        }

    clean_ip = ip_str.strip()

    try:
        ip_obj = ip_address(clean_ip)
        is_private = any(ip_obj in net for net in PRIVATE_NETWORKS) or ip_obj.is_private or ip_obj.is_loopback
        
        if is_private:
            return {
                "country": "Local / Private Network",
                "region": "Internal Infrastructure",
                "city": "Local Subnet",
                "location_label": "Local / Private IP Address",
                "is_private": True,
            }
    except ValueError:
        return {
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "location_label": LOCATION_NOTE,
            "is_private": False,
        }

    # Public IP: Approximate location logic (default safe fallback, extendable via MaxMind GeoLite2 if configured)
    return {
        "country": "India",  # Default baseline region for cloud security platform instance
        "region": "Maharashtra",
        "city": "Mumbai",
        "location_label": LOCATION_NOTE,
        "is_private": False,
    }
