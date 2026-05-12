import argparse
import json
import logging
import time
from pathlib import Path


class Vulnerability:
    """Represents one vulnerability found on a host."""

    def __init__(self, cve, cvss, description):
        self.cve = cve
        self.cvss = float(cvss)
        self.description = description


class Host:
    """Represents one system being analyzed."""

    def __init__(self, hostname, ip, criticality, internet_facing, vulnerabilities):
        self.hostname = hostname
        self.ip = ip
        self.criticality = criticality.lower()
        self.internet_facing = internet_facing
        self.vulnerabilities = vulnerabilities

    def calculate_risk_score(self):
        """Calculate risk score based on CVSS, criticality, and exposure."""
        if not self.vulnerabilities:
            return 0

        highest_cvss = max(vuln.cvss for vuln in self.vulnerabilities)
        score = highest_cvss * 10

        if self.criticality == "critical":
            score += 20
        elif self.criticality == "high":
            score += 10
        elif self.criticality == "medium":
            score += 5

        if self.internet_facing:
            score += 15

        return min(round(score), 100)

    def get_risk_level(self):
        """Convert risk score into a readable level."""
        score = self.calculate_risk_score()

        if score >= 90:
            return "Critical"
        elif score >= 70:
            return "High"
        elif score >= 40:
            return "Medium"
        return "Low"


class RiskAnalyzer:
    """Analyzes hosts and ranks them by risk."""

    def __init__(self, hosts):
        self.hosts = hosts

    def analyze(self, scan_date):
        """Analyze all hosts and return report data."""
        results = []

        for host in self.hosts:
            results.append({
                "hostname": host.hostname,
                "ip": host.ip,
                "criticality": host.criticality,
                "internet_facing": host.internet_facing,
                "vulnerability_count": len(host.vulnerabilities),
                "risk_score": host.calculate_risk_score(),
                "risk_level": host.get_risk_level()
            })

        results.sort(key=lambda item: item["risk_score"], reverse=True)

        high_risk_hosts = [
            host for host in results
            if host["risk_level"] in ["Critical", "High"]
        ]

        return {
            "scan_date": scan_date,
            "total_hosts": len(results),
            "high_risk_hosts": len(high_risk_hosts),
            "top_priority_hosts": results
        }


class ReportGenerator:
    """Creates report files."""

    def save_json_report(self, results, output_file):
        """Save results to a JSON report."""
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as file:
            json.dump(results, file, indent=4)

    def save_text_summary(self, results, summary_file):
        """Save a readable text summary report."""
        Path(summary_file).parent.mkdir(parents=True, exist_ok=True)

        with open(summary_file, "w", encoding="utf-8") as file:
            file.write("VULNPRIORITY PRO SUMMARY REPORT\n")
            file.write("=" * 40 + "\n\n")
            file.write(f"Scan Date: {results['scan_date']}\n")
            file.write(f"Total Hosts: {results['total_hosts']}\n")
            file.write(f"High Risk Hosts: {results['high_risk_hosts']}\n\n")
            file.write("TOP PRIORITY HOSTS\n")
            file.write("-" * 40 + "\n")

            for host in results["top_priority_hosts"]:
                file.write(
                    f"{host['hostname']} ({host['ip']}) - "
                    f"Score: {host['risk_score']} - "
                    f"Level: {host['risk_level']}\n"
                )


def setup_logging(verbose=False):
    """Set up logging."""
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        filename="vulnpriority.log",
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        force=True
    )


def load_json_file(input_file):
    """Load JSON data from a file."""
    try:
        with open(input_file, "r", encoding="utf-8") as file:
            return json.load(file)

    except FileNotFoundError as error:
        raise FileNotFoundError(f"Input file not found: {input_file}") from error

    except PermissionError as error:
        raise PermissionError(f"Permission denied for file: {input_file}") from error

    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid JSON file: {input_file}") from error


def validate_input_data(data):
    """Validate required JSON fields."""
    if not isinstance(data, dict):
        raise ValueError("Input JSON must be an object")

    if "scan_date" not in data:
        raise ValueError("Input JSON is missing required field: scan_date")

    if "hosts" not in data:
        raise ValueError("Input JSON is missing required field: hosts")

    if not isinstance(data["hosts"], list):
        raise ValueError("hosts must be a list")

    for index, host in enumerate(data["hosts"]):
        required_host_fields = [
            "hostname",
            "ip",
            "criticality",
            "internet_facing",
            "vulnerabilities"
        ]

        for field in required_host_fields:
            if field not in host:
                raise ValueError(f"Host {index} is missing required field: {field}")

        if not isinstance(host["vulnerabilities"], list):
            raise ValueError(f"Host {index} vulnerabilities must be a list")

        for vuln_index, vuln in enumerate(host["vulnerabilities"]):
            if "cve" not in vuln:
                raise ValueError(f"Host {index} vulnerability {vuln_index} is missing cve")

            if "cvss" not in vuln:
                raise ValueError(f"Host {index} vulnerability {vuln_index} is missing cvss")

            try:
                float(vuln["cvss"])
            except ValueError as error:
                raise ValueError(
                    f"Host {index} vulnerability {vuln_index} has invalid cvss"
                ) from error


def build_hosts(data):
    """Build Host objects from validated JSON data."""
    hosts = []

    for item in data["hosts"]:
        vulnerabilities = []

        for vuln in item["vulnerabilities"]:
            vulnerabilities.append(
                Vulnerability(
                    vuln["cve"],
                    vuln["cvss"],
                    vuln.get("description", "No description")
                )
            )

        hosts.append(
            Host(
                item["hostname"],
                item["ip"],
                item["criticality"],
                item["internet_facing"],
                vulnerabilities
            )
        )

    return hosts


def create_parser():
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="VulnPriority Pro - Vulnerability Risk Prioritization Tool"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to vulnerability JSON input file"
    )

    parser.add_argument(
        "--output",
        default="reports/risk_report.json",
        help="Path to JSON output report"
    )

    parser.add_argument(
        "--summary",
        default="reports/summary_report.txt",
        help="Path to text summary report"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed logging"
    )

    return parser


def run_tool(input_file, output_file, summary_file):
    """Run the main tool logic."""
    data = load_json_file(input_file)
    validate_input_data(data)

    hosts = build_hosts(data)
    analyzer = RiskAnalyzer(hosts)
    results = analyzer.analyze(data["scan_date"])

    report_generator = ReportGenerator()
    report_generator.save_json_report(results, output_file)
    report_generator.save_text_summary(results, summary_file)

    return results


def print_banner():
    """Display a clean terminal banner for demo mode."""
    print()
    print("╔════════════════════════════════════════════╗")
    print("║              VulnPriority Pro             ║")
    print("║      Vulnerability Risk Analyzer          ║")
    print("╚════════════════════════════════════════════╝")
    print()


def loading_step(message, delay=0.25):
    """Display one animated terminal loading step."""
    frames = ["|", "/", "-", "\\"]

    for frame in frames:
        print(f"\r[{frame}] {message}", end="", flush=True)
        time.sleep(delay)

    print(f"\r[✓] {message}")


def run_verbose_intro():
    """Display animated startup steps when verbose mode is enabled."""
    print_banner()
    loading_step("Loading vulnerability data...")
    loading_step("Validating input structure...")
    loading_step("Calculating host risk scores...")
    loading_step("Generating reports...")
    print()

def print_banner():
    """Display a clean terminal banner for demo mode."""
    print()
    print("╔════════════════════════════════════════════╗")
    print("║              VulnPriority Pro             ║")
    print("║      Vulnerability Risk Analyzer          ║")
    print("╚════════════════════════════════════════════╝")
    print()


def loading_step(message, delay=0.25):
    """Display one animated terminal loading step."""
    frames = ["|", "/", "-", "\\"]

    for frame in frames:
        print(f"\r[{frame}] {message}", end="", flush=True)
        time.sleep(delay)

    print(f"\r[✓] {message}")


def run_verbose_intro():
    """Display animated startup steps when verbose mode is enabled."""
    print_banner()
    loading_step("Loading vulnerability data...")
    loading_step("Validating input structure...")
    loading_step("Calculating host risk scores...")
    loading_step("Generating reports...")
    print()

def main():
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    setup_logging(args.verbose)

    if args.verbose:
        run_verbose_intro()

    try:
        logging.info("Starting VulnPriority Pro")

        results = run_tool(args.input, args.output, args.summary)

        logging.info("Analysis completed successfully")

        print("VulnPriority Pro analysis complete.")
        print(f"Total hosts analyzed: {results['total_hosts']}")
        print(f"High-risk hosts found: {results['high_risk_hosts']}")
        print(f"JSON report saved to: {args.output}")
        print(f"Summary report saved to: {args.summary}")

        return 0

    except Exception as error:
        logging.error("Program failed: %s", error)
        print(f"ERROR: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())