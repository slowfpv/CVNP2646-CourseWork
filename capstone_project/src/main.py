import argparse
import json
import logging
from pathlib import Path


class Vulnerability:
    def __init__(self, cve, cvss, description):
        self.cve = cve
        self.cvss = float(cvss)
        self.description = description


class Host:
    def __init__(self, hostname, ip, criticality, internet_facing, vulnerabilities):
        self.hostname = hostname
        self.ip = ip
        self.criticality = criticality
        self.internet_facing = internet_facing
        self.vulnerabilities = vulnerabilities

    def calculate_risk_score(self):
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
        score = self.calculate_risk_score()

        if score >= 90:
            return "Critical"
        elif score >= 70:
            return "High"
        elif score >= 40:
            return "Medium"
        else:
            return "Low"


class RiskAnalyzer:
    def __init__(self, hosts):
        self.hosts = hosts

    def analyze(self, scan_date):
        results = []

        for host in self.hosts:
            score = host.calculate_risk_score()
            level = host.get_risk_level()

            results.append({
                "hostname": host.hostname,
                "ip": host.ip,
                "criticality": host.criticality,
                "internet_facing": host.internet_facing,
                "vulnerability_count": len(host.vulnerabilities),
                "risk_score": score,
                "risk_level": level
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
    def save_json_report(self, results, output_file):
        with open(output_file, "w") as file:
            json.dump(results, file, indent=4)

    def save_text_summary(self, results, summary_file):
        with open(summary_file, "w") as file:
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
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        filename="vulnpriority.log",
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )


def load_json_file(input_file):
    try:
        with open(input_file, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        raise FileNotFoundError(f"Input file not found: {input_file}")
    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON file: {input_file}")


def build_hosts(data):
    hosts = []

    for item in data.get("hosts", []):
        vulnerabilities = []

        for vuln in item.get("vulnerabilities", []):
            vulnerabilities.append(
                Vulnerability(
                    vuln.get("cve", "UNKNOWN"),
                    vuln.get("cvss", 0),
                    vuln.get("description", "No description")
                )
            )

        hosts.append(
            Host(
                item.get("hostname", "unknown-host"),
                item.get("ip", "0.0.0.0"),
                item.get("criticality", "low"),
                item.get("internet_facing", False),
                vulnerabilities
            )
        )

    return hosts


def create_parser():
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


def main():
    parser = create_parser()
    args = parser.parse_args()

    setup_logging(args.verbose)

    try:
        logging.info("Starting VulnPriority Pro")

        Path("reports").mkdir(exist_ok=True)

        data = load_json_file(args.input)
        scan_date = data.get("scan_date", "unknown")

        hosts = build_hosts(data)
        analyzer = RiskAnalyzer(hosts)
        results = analyzer.analyze(scan_date)

        report_generator = ReportGenerator()
        report_generator.save_json_report(results, args.output)
        report_generator.save_text_summary(results, args.summary)

        logging.info("Analysis completed successfully")

        print("VulnPriority Pro analysis complete.")
        print(f"Total hosts analyzed: {results['total_hosts']}")
        print(f"High-risk hosts found: {results['high_risk_hosts']}")
        print(f"JSON report saved to: {args.output}")
        print(f"Summary report saved to: {args.summary}")

    except Exception as error:
        logging.error("Program failed: %s", error)
        print(f"ERROR: {error}")


if __name__ == "__main__":
    main()
