"""
hex_converter.py
Week 3 - Hex Address Converter

Converts between:
- Hex -> Decimal (common for memory addresses, offsets, color codes)
  Use: int(hex_string, 16)
- Decimal -> Hex
  Use: hex(decimal_int)

Note:
- For hex -> decimal using int(), you can store hex without the "0x" prefix.
"""

def hex_to_decimal(hex_value: str) -> int:
    """
    Convert a hex string into an integer.
    Accepts values like "FF", "2A", "100" (no 0x needed).
    """
    # int(value, 16) interprets the string using base-16
    return int(hex_value, 16)


def decimal_to_hex(decimal_value: int) -> str:
    """
    Convert an integer into a hex string with '0x' prefix.
    """
    # hex(value) returns a string like "0xff"
    return hex(decimal_value)


if __name__ == "__main__":
    # Required: multiple test values (e.g., 0xFF, 0x2A, 0x100)
    # We'll store them without "0x" per the assignment hint.
    test_hex_values = ["FF", "2A", "100"]

    print("=" * 55)
    print("Hex Address Converter")
    print("=" * 55)

    for hv in test_hex_values:
        dec = hex_to_decimal(hv)
        back_to_hex = decimal_to_hex(dec)

        # f-string formatted output
        print(f"Hex 0x{hv} -> Decimal {dec} -> Back to Hex {back_to_hex}")

    print("=" * 55)
