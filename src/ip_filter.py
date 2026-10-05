import ipaddress


def get_public_ip(value):
    """Return a valid public IP, or None if it should not be queried."""
    if not isinstance(value, str):
        return None

    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        # Ignore missing or malformed IP addresses.
        return None

    # Private and other non-global addresses should not go to reputation APIs.
    return str(address) if address.is_global else None