"""
CVNP2646 - Week 2
Task 1: IP Address Validator
"""

def validate_ip(ip_address: str) -> bool:
    """
    Validates an IPv4 address.
    Rules:
    - Must have exactly 4 octets separated by dots
    - Each octet must be an integer from 0 to 255
    """
    try:
        parts = ip_address.split(".")
        if len(parts) != 4:
            return False

        for part in parts:
            # Reject empty octets like "192..1.1"
            if part == "":
                return False

            # Convert to integer
            num = int(part)

            # Range check
            if num < 0 or num > 255:
                return False

        return True

    except (ValueError, TypeError):
        return False


if __name__ == "__main__":
    test_ips = [
        "192.168.1.1",     # valid
        "10.0.0.256",      # invalid (256 out of range)
        "abc.1.1.1",       # invalid (not numbers)
        "172.16.0",        # invalid (not 4 octets)
    ]

    print("=== IP Address Validator Tests ===")
    for ip in test_ips:
        result = validate_ip(ip)
        print(f"IP: {ip:<15} -> {'VALID' if result else 'INVALID'}")
