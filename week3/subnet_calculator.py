"""
subnet_calculator.py
Week 3 - Network Subnet Calculator

Calculates:
- Total IP addresses in the subnet: 2 ** (32 - subnet_mask)
- Usable host IPs: total_ips - 2 (network + broadcast)
- Network class based on first octet:
  A: 1-127, B: 128-191, C: 192-223 (otherwise: D/E or invalid for typical host networks)
"""

def get_network_class(first_octet: int) -> str:
    """Return the network class name based on the first octet."""
    if 1 <= first_octet <= 127:
        return "A"
    if 128 <= first_octet <= 191:
        return "B"
    if 192 <= first_octet <= 223:
        return "C"
    if 224 <= first_octet <= 239:
        return "D (Multicast)"
    if 240 <= first_octet <= 255:
        return "E (Reserved)"
    return "Invalid"


def calculate_subnet_info(network_ip: str, subnet_mask: int) -> dict:
    """
    Calculate subnet information for a given network IP and subnet mask.
    Returns a dict with results.
    """
    try:
        # Basic parsing and validation of IP format
        octets = network_ip.strip().split(".")
        if len(octets) != 4:
            raise ValueError("IP must have exactly 4 octets.")

        octets_int = [int(o) for o in octets]
        for o in octets_int:
            if o < 0 or o > 255:
                raise ValueError("Each octet must be between 0 and 255.")

        if subnet_mask < 0 or subnet_mask > 32:
            raise ValueError("Subnet mask must be between 0 and 32.")

        first_octet = octets_int[0]
        net_class = get_network_class(first_octet)

        host_bits = 32 - subnet_mask
        total_ips = 2 ** host_bits

        # Usable hosts typically subtract 2, but /31 and /32 are special cases
        if subnet_mask >= 31:
            usable_hosts = 0
        else:
            usable_hosts = total_ips - 2

        return {
            "network_ip": network_ip,
            "subnet_mask": subnet_mask,
            "host_bits": host_bits,
            "total_ips": total_ips,
            "usable_hosts": usable_hosts,
            "network_class": net_class,
            "first_octet": first_octet
        }

    except Exception as e:
        return {"error": str(e)}


def print_report(result: dict) -> None:
    """Print a formatted report using f-strings."""
    if "error" in result:
        print(f"[ERROR] {result['error']}")
        return

    print("=" * 55)
    print(f"Network Subnet Calculator Report")
    print("=" * 55)
    print(f"Network IP:      {result['network_ip']}")
    print(f"Subnet Mask:     /{result['subnet_mask']}")
    print(f"Host Bits:       {result['host_bits']}")
    print(f"Total IPs:       {result['total_ips']}  (2 ** (32 - {result['subnet_mask']}))")
    print(f"Usable Hosts:    {result['usable_hosts']}  (Total - 2)")
    print(f"First Octet:     {result['first_octet']}")
    print(f"Network Class:   {result['network_class']}")
    print(f"Summary: Subnet /{result['subnet_mask']}: {result['total_ips']} total IPs, {result['usable_hosts']} usable hosts")
    print("=" * 55)
    print()


if __name__ == "__main__":
    # Test cases (required: at least 2 masks)
    tests = [
        ("192.168.1.0", 24),
        ("10.0.0.0", 28),
    ]

    for network_ip, subnet_mask in tests:
        result = calculate_subnet_info(network_ip, subnet_mask)
        print_report(result)
