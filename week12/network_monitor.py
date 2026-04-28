import argparse
import json
import logging
import sys
from pathlib import Path


class NetworkConfig:
    """Configuration settings for network traffic analysis."""

    DEFAULT_PORT_SCAN_THRESHOLD = 25
    DEFAULT_SYN_FLOOD_THRESHOLD = 100
    DEFAULT_PACKET_RATE_THRESHOLD = 1000

    def __init__(self, port_scan_threshold=None, syn_flood_threshold=None):
        self.port_scan_threshold = port_scan_threshold or self.DEFAULT_PORT_SCAN_THRESHOLD
        self.syn_flood_threshold = syn_flood_threshold or self.DEFAULT_SYN_FLOOD_THRESHOLD
        self.packet_rate_threshold = self.DEFAULT_PACKET_RATE_THRESHOLD


def setup_logging(log_file="network_monitor.log", log_level="INFO"):
    """Set up logging for the program."""
    logger = logging.getLogger("network_monitor")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    ))

    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, log_level))
    console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def parse_packet_line(line: str) -> dict:
    """Parse one packet line from the traffic log."""
    parts = [item.strip() for item in line.split(",")]

    if len(parts) != 6:
        raise ValueError("Packet line must have 6 fields")

    src_ip, dst_ip, src_port, dst_port, protocol, flags = parts

    try:
        src_port = int(src_port)
        dst_port = int(dst_port)
    except ValueError:
        raise ValueError("Ports must be numbers")

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol.upper(),
        "flags": flags.upper()
    }


def is_syn_packet(packet: dict) -> bool:
    """Check if a packet is a TCP SYN packet."""
    return packet["protocol"] == "TCP" and packet["flags"] == "SYN"


def detect_port_scan(packets: list, src_ip: str, threshold: int) -> bool:
    """Check if one source IP touched too many destination ports."""
    ports = set()

    for packet in packets:
        if packet["src_ip"] == src_ip:
            ports.add(packet["dst_port"])

    return len(ports) > threshold


def detect_syn_flood(packets: list, src_ip: str, threshold: int) -> bool:
    """Check if one source IP sent too many SYN packets."""
    count = 0

    for packet in packets:
        if packet["src_ip"] == src_ip and is_syn_packet(packet):
            count += 1

    return count > threshold


def load_traffic_log(filepath: str) -> list:
    """Load packet data from a traffic log file."""
    logger = logging.getLogger("network_monitor")
    packets = []

    try:
        with open(filepath, "r") as file:
            for line_number, line in enumerate(file, start=1):
                line = line.strip()

                if line == "":
                    continue

                try:
                    packet = parse_packet_line(line)
                    packets.append(packet)
                    logger.debug("Parsed packet on line %s", line_number)

                except ValueError as error:
                    logger.error("Error on line %s: %s", line_number, error)

    except FileNotFoundError:
        logger.error("File was not found: %s", filepath)
        raise

    except PermissionError:
        logger.error("Permission denied for file: %s", filepath)
        raise

    logger.info("Loaded %s packets", len(packets))
    return packets


def analyze_traffic(packets: list, config: NetworkConfig) -> dict:
    """Analyze traffic and return results."""
    logger = logging.getLogger("network_monitor")

    source_ips = set()
    for packet in packets:
        source_ips.add(packet["src_ip"])

    port_scans = []
    syn_floods = []

    for src_ip in source_ips:
        logger.debug("Checking source IP: %s", src_ip)

        if detect_port_scan(packets, src_ip, config.port_scan_threshold):
            logger.warning("Port scan detected from %s", src_ip)
            port_scans.append(src_ip)

        if detect_syn_flood(packets, src_ip, config.syn_flood_threshold):
            logger.warning("SYN flood detected from %s", src_ip)
            syn_floods.append(src_ip)

    results = {
        "total_packets": len(packets),
        "unique_source_ips": len(source_ips),
        "port_scans": port_scans,
        "syn_floods": syn_floods
    }

    logger.info("Analysis complete")
    return results


def create_parser():
    """Create the command line parser."""
    parser = argparse.ArgumentParser(
        description="Network Traffic Monitor - Detect suspicious network traffic"
    )

    parser.add_argument("input_file", type=Path, help="Traffic log file")
    parser.add_argument("-o", "--output", type=Path, default=Path("results.json"))
    parser.add_argument("-p", "--port-scan-threshold", type=int, default=25)
    parser.add_argument("-s", "--syn-flood-threshold", type=int, default=100)
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--version", action="version", version="network_monitor.py 1.0.0")

    return parser


def validate_args(args):
    """Validate command line arguments."""
    if not args.input_file.exists():
        raise FileNotFoundError(f"Input file not found: {args.input_file}")

    if not args.input_file.is_file():
        raise ValueError("Input path must be a file")

    if args.port_scan_threshold < 1:
        raise ValueError("Port scan threshold must be positive")

    if args.syn_flood_threshold < 1:
        raise ValueError("SYN flood threshold must be positive")

    if args.verbose:
        args.log_level = "DEBUG"


def main():
    """Main program function."""
    parser = create_parser()
    args = parser.parse_args()

    try:
        validate_args(args)

        logger = setup_logging(log_level=args.log_level)
        logger.info("Network Monitor starting")

        config = NetworkConfig(
            port_scan_threshold=args.port_scan_threshold,
            syn_flood_threshold=args.syn_flood_threshold
        )

        packets = load_traffic_log(str(args.input_file))
        results = analyze_traffic(packets, config)

        with open(args.output, "w") as file:
            json.dump(results, file, indent=4)

        print("\nAnalysis complete")
        print(f"Total packets: {results['total_packets']}")
        print(f"Port scans found: {len(results['port_scans'])}")
        print(f"SYN floods found: {len(results['syn_floods'])}")
        print(f"Results saved to: {args.output}")

        return 0

    except FileNotFoundError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    except ValueError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    except Exception as error:
        print(f"FATAL ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())