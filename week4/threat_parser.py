#!/usr/bin/env python3
# threat_parser.py
# Parses JSON threat intelligence data and generates security reports

import json
from datetime import datetime


def load_threat_data(filename: str) -> dict:
    """Loads threat intelligence data from a JSON file."""
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"❌ Error: Could not find '{filename}'. Make sure it's in the same folder.")
        raise
    except json.JSONDecodeError as e:
        print(f"❌ Error: '{filename}' is not valid JSON. Details: {e}")
        raise


def extract_ips(indicators) -> list:
    """
    Extract IPs from indicators in a flexible way.

    Supports:
      - {"ips": ["1.2.3.4", "5.6.7.8"]}
      - {"ips": [{"value":"1.2.3.4"}, {"value":"5.6.7.8"}]}
      - {"ips": "1.2.3.4"} (single string)
      - ["1.2.3.4", "5.6.7.8"] (list directly)
      - [] or missing -> returns []
    """
    if indicators is None:
        return []

    # If indicators is already a list of IP strings
    if isinstance(indicators, list):
        return [str(x) for x in indicators]

    # If indicators is a dict with "ips"
    if isinstance(indicators, dict):
        ips = indicators.get("ips", [])
        if isinstance(ips, str):
            return [ips]
        if isinstance(ips, list):
            # list could be strings or dicts
            extracted = []
            for item in ips:
                if isinstance(item, str):
                    extracted.append(item)
                elif isinstance(item, dict) and "value" in item:
                    extracted.append(str(item["value"]))
            return extracted

    return []


def analyze_threats(threat_data: dict) -> dict:
    """Analyzes threat data and generates statistics."""
    threats = threat_data.get("threats", [])

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    all_ips = []
    active_exploits = []

    for threat in threats:
        # --- Severity counting (safe) ---
        severity = str(threat.get("severity", "UNKNOWN")).upper()
        if severity not in severity_counts:
            severity_counts["UNKNOWN"] += 1
        else:
            severity_counts[severity] += 1

        # --- IP extraction (safe/flexible) ---
        indicators = threat.get("indicators")
        ips = extract_ips(indicators)
        all_ips.extend(ips)

        # --- Active exploit collection (safe) ---
        if bool(threat.get("active_exploit", False)):
            active_exploits.append(
                {
                    "id": threat.get("id", "N/A"),
                    "type": threat.get("type", "N/A"),
                    "description": threat.get("description", "No description provided"),
                }
            )

    total_threats = len(threats)
    if total_threats == 0:
        critical_percentage = 0.0
    else:
        critical_percentage = (severity_counts["CRITICAL"] / total_threats) * 100

    unique_ips = sorted(set(all_ips))

    return {
        "total_threats": total_threats,
        "severity_counts": severity_counts,
        "unique_ips": unique_ips,
        "total_ips": len(all_ips),
        "active_exploits": active_exploits,
        "critical_percentage": critical_percentage,
    }


def generate_report(threat_data: dict, analysis: dict, output_file: str) -> list:
    """Generates a formatted text report and saves to a file."""
    report_lines = []

    feed_name = threat_data.get("feed_name", "Unknown Feed")
    feed_date = threat_data.get("date", "Unknown Date")

    report_lines.append("=" * 70)
    report_lines.append("THREAT INTELLIGENCE ANALYSIS REPORT")
    report_lines.append("=" * 70)
    report_lines.append(f"Feed: {feed_name}")
    report_lines.append(f"Date: {feed_date}")
    report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("")

    report_lines.append("-" * 70)
    report_lines.append("SUMMARY STATISTICS")
    report_lines.append("-" * 70)
    report_lines.append(f"Total Threats: {analysis['total_threats']}")
    report_lines.append(f"Total Malicious IPs (raw count): {analysis['total_ips']}")
    report_lines.append(f"Unique IPs: {len(analysis['unique_ips'])}")
    report_lines.append(f"Active Exploits: {len(analysis['active_exploits'])}")
    report_lines.append("")

    report_lines.append("-" * 70)
    report_lines.append("SEVERITY BREAKDOWN")
    report_lines.append("-" * 70)
    for severity, count in analysis["severity_counts"].items():
        report_lines.append(f"{severity:10}: {count} threats")
    report_lines.append(f"\nCRITICAL threats: {analysis['critical_percentage']:.1f}%")
    report_lines.append("")

    report_lines.append("-" * 70)
    report_lines.append("MALICIOUS IP ADDRESSES")
    report_lines.append("-" * 70)
    if analysis["unique_ips"]:
        for ip in analysis["unique_ips"]:
            report_lines.append(f"  - {ip}")
    else:
        report_lines.append("  (No IPs found)")
    report_lines.append("")

    report_lines.append("-" * 70)
    report_lines.append("ACTIVE EXPLOITS (IMMEDIATE ATTENTION REQUIRED)")
    report_lines.append("-" * 70)
    if analysis["active_exploits"]:
        for exploit in analysis["active_exploits"]:
            report_lines.append(f"\n{exploit['id']} ({str(exploit['type']).upper()})")
            report_lines.append(f"  Description: {exploit['description']}")
    else:
        report_lines.append("  (No active exploits found)")
    report_lines.append("")

    report_lines.append("=" * 70)
    report_lines.append("END OF REPORT")
    report_lines.append("=" * 70)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    return report_lines


if __name__ == "__main__":
    print("=" * 70)
    print("THREAT INTELLIGENCE PARSER")
    print("=" * 70)
    print()

    filename = "threats.json"
    output = "threat_report.txt"

    print(f"📖 Loading threat data from {filename}...")
    threat_data = load_threat_data(filename)
    threats = threat_data.get("threats", [])
    print(f"✓ Loaded {len(threats)} threats from {threat_data.get('feed_name', 'Unknown Feed')}")
    print()

    print("🔍 Analyzing threat intelligence...")
    analysis = analyze_threats(threat_data)
    print("✓ Analysis complete")
    print()

    print("📝 Generating security report...")
    report_lines = generate_report(threat_data, analysis, output)
    print(f"✓ Report saved to {output}")
    print()

    print("=" * 70)
    print("REPORT PREVIEW")
    print("=" * 70)
    for line in report_lines:
        print(line)
