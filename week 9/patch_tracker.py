import json
from datetime import datetime


CRITICALITY_POINTS = {
    "critical": 40,
    "high": 25,
    "medium": 10,
    "low": 5
}

ENVIRONMENT_POINTS = {
    "production": 15,
    "staging": 8,
    "development": 3
}


def load_inventory(filepath):
    """Load host inventory JSON file and return list of host dictionaries."""
    with open(filepath, "r", encoding="utf-8") as file:
        return json.load(file)


def calculate_days_since_patch(host):
    """Calculate days since the host was last patched."""
    last_patch = datetime.strptime(host["last_patch_date"], "%Y-%m-%d")
    return (datetime.now() - last_patch).days


def filter_by_os(hosts, os_type):
    """Return hosts whose OS contains the given os_type (case-insensitive)."""
    return [h for h in hosts if os_type.lower() in h["os"].lower()]


def filter_by_criticality(hosts, level):
    """Return hosts matching the exact criticality level."""
    return [h for h in hosts if h["criticality"].lower() == level.lower()]


def filter_by_environment(hosts, env):
    """Return hosts matching the exact environment."""
    return [h for h in hosts if h["environment"].lower() == env.lower()]


def filter_critical_production(hosts):
    """Return hosts that are both critical and in production."""
    return [
        h for h in hosts
        if h["criticality"].lower() == "critical"
        and h["environment"].lower() == "production"
    ]


def calculate_risk_score(host):
    """Calculate point-based risk score capped at 100."""
    score = 0

    criticality = host.get("criticality", "").lower()
    environment = host.get("environment", "").lower()
    tags = [tag.lower() for tag in host.get("tags", [])]
    days_since_patch = host.get("days_since_patch", 0)

    score += CRITICALITY_POINTS.get(criticality, 0)

    if days_since_patch > 90:
        score += 30
    elif days_since_patch > 60:
        score += 20
    elif days_since_patch > 30:
        score += 10

    score += ENVIRONMENT_POINTS.get(environment, 0)

    if "pci-scope" in tags:
        score += 10
    if "hipaa" in tags:
        score += 10
    if "internet-facing" in tags:
        score += 15

    return min(score, 100)


def get_risk_level(score):
    """Convert numeric risk score into risk level string."""
    if score >= 70:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 25:
        return "medium"
    else:
        return "low"


def get_high_risk_hosts(hosts, threshold=50):
    """Return high-risk hosts sorted by risk_score descending."""
    high_risk = [h for h in hosts if h.get("risk_score", 0) >= threshold]
    return sorted(high_risk, key=lambda h: h["risk_score"], reverse=True)


def analyze_inventory(hosts):
    """Main analysis pipeline: add days_since_patch, risk_score, and risk_level."""
    for host in hosts:
        host["days_since_patch"] = calculate_days_since_patch(host)
        host["risk_score"] = calculate_risk_score(host)
        host["risk_level"] = get_risk_level(host["risk_score"])
    return hosts


def generate_json_report(hosts, high_risk_hosts):
    """Generate JSON report structure for automation."""
    risk_distribution = {
        "critical": sum(1 for h in hosts if h["risk_level"] == "critical"),
        "high": sum(1 for h in hosts if h["risk_level"] == "high"),
        "medium": sum(1 for h in hosts if h["risk_level"] == "medium"),
        "low": sum(1 for h in hosts if h["risk_level"] == "low")
    }

    report = {
        "report_date": datetime.now().isoformat(timespec="seconds"),
        "report_type": "High Risk Host Assessment",
        "total_hosts": len(hosts),
        "total_high_risk": len(high_risk_hosts),
        "risk_distribution": risk_distribution,
        "high_risk_hosts": []
    }

    for host in high_risk_hosts:
        report["high_risk_hosts"].append({
            "hostname": host["hostname"],
            "risk_score": host["risk_score"],
            "risk_level": host["risk_level"],
            "days_since_patch": host["days_since_patch"],
            "criticality": host["criticality"],
            "environment": host["environment"],
            "tags": host.get("tags", [])
        })

    return report


def generate_text_summary(hosts, high_risk_hosts):
    """Generate formatted text summary for managers."""
    generated_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    critical_count = sum(1 for h in hosts if h["risk_level"] == "critical")
    high_count = sum(1 for h in hosts if h["risk_level"] == "high")
    medium_count = sum(1 for h in hosts if h["risk_level"] == "medium")
    low_count = sum(1 for h in hosts if h["risk_level"] == "low")
    over_90_days = sum(1 for h in hosts if h["days_since_patch"] > 90)

    percent_high_risk = 0
    if len(hosts) > 0:
        percent_high_risk = (len(high_risk_hosts) / len(hosts)) * 100

    lines = []
    lines.append("=" * 64)
    lines.append("          WEEKLY PATCH COMPLIANCE SUMMARY REPORT")
    lines.append("=" * 64)
    lines.append(f"Generated: {generated_time}")
    lines.append("")
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 64)
    lines.append(f"Total Systems Analyzed:        {len(hosts)}")
    lines.append(f"High-Risk Systems Identified:  {len(high_risk_hosts)} ({percent_high_risk:.1f}%)")
    lines.append(f"Critical Priority Systems:     {critical_count}")
    lines.append(f"Immediate Action Required:     {over_90_days} systems >90 days unpatched")
    lines.append("")
    lines.append("RISK DISTRIBUTION")
    lines.append("-" * 64)
    lines.append(f"Critical (≥70 points):         {critical_count} systems")
    lines.append(f"High (50-69 points):           {high_count} systems")
    lines.append(f"Medium (25-49 points):         {medium_count} systems")
    lines.append(f"Low (<25 points):              {low_count} systems")
    lines.append("")
    lines.append("TOP 5 HIGHEST RISK SYSTEMS")
    lines.append("-" * 64)

    top_five = high_risk_hosts[:5]
    if not top_five:
        lines.append("No high-risk systems identified.")
    else:
        for i, host in enumerate(top_five, start=1):
            tags_text = ", ".join(host.get("tags", []))
            lines.append(
                f"{i}. {host['hostname']} (Score: {host['risk_score']}, {host['risk_level'].capitalize()})"
            )
            lines.append(
                f"   Last Patched: {host['days_since_patch']} days ago | "
                f"{host['environment'].capitalize()} | Tags: {tags_text}"
            )
            lines.append("")

    pci_hosts = [
        h for h in high_risk_hosts
        if "pci-scope" in [tag.lower() for tag in h.get("tags", [])]
    ]
    critical_hosts = [h for h in high_risk_hosts if h["risk_level"] == "critical"]

    lines.append("RECOMMENDED ACTIONS")
    lines.append("-" * 64)
    lines.append("IMMEDIATE (Next 48 hours):")
    lines.append(f"• Patch {len(critical_hosts)} critical-risk systems")
    lines.append("• Review emergency change control procedures")
    lines.append("")
    lines.append("THIS WEEK (Next 7 days):")
    lines.append(f"• Schedule maintenance windows for {len(high_risk_hosts)} high-risk systems")
    lines.append("• Test patches in staging environment first")
    lines.append("")
    lines.append("THIS MONTH (Next 30 days):")
    lines.append("• Implement automated patch deployment for dev/test systems")
    lines.append("• Review and update patch management SOP")
    lines.append("")
    lines.append("COMPLIANCE NOTES")
    lines.append("-" * 64)
    lines.append(
        f"CIS Control 7.3: Critical vulnerabilities should be remediated "
        f"within 15 days. Currently {critical_count} systems are in critical risk range."
    )
    lines.append("")
    lines.append(
        f"PCI-DSS 6.2: Systems in PCI scope must be patched promptly. "
        f"Currently {len(pci_hosts)} high-risk PCI-scoped systems need attention."
    )
    lines.append("")
    lines.append("=" * 64)

    return "\n".join(lines)


def generate_html_report(hosts):
    """Generate bonus HTML report with color-coded rows."""
    color_map = {
        "critical": "#f8d7da",
        "high": "#fff3cd",
        "medium": "#d1ecf1",
        "low": "#d4edda"
    }

    rows = []
    sorted_hosts = sorted(hosts, key=lambda h: h["risk_score"], reverse=True)

    for host in sorted_hosts:
        tags_text = ", ".join(host.get("tags", []))
        bg_color = color_map.get(host["risk_level"], "#ffffff")
        rows.append(
            f"<tr style='background-color:{bg_color};'>"
            f"<td>{host['hostname']}</td>"
            f"<td>{host['ip_address']}</td>"
            f"<td>{host['os']}</td>"
            f"<td>{host['criticality']}</td>"
            f"<td>{host['environment']}</td>"
            f"<td>{host['days_since_patch']}</td>"
            f"<td>{host['risk_score']}</td>"
            f"<td>{host['risk_level'].capitalize()}</td>"
            f"<td>{tags_text}</td>"
            f"</tr>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Patch Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
        }}
        h1 {{
            color: #333;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th, td {{
            border: 1px solid #999;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #222;
            color: white;
        }}
        tr:hover {{
            opacity: 0.9;
        }}
    </style>
</head>
<body>
    <h1>Weekly Patch Compliance Report</h1>
    <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    <table>
        <thead>
            <tr>
                <th>Hostname</th>
                <th>IP Address</th>
                <th>OS</th>
                <th>Criticality</th>
                <th>Environment</th>
                <th>Days Since Patch</th>
                <th>Risk Score</th>
                <th>Risk Level</th>
                <th>Tags</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
</body>
</html>
"""
    return html


def main():
    """Run patch analysis pipeline and save output files."""
    hosts = load_inventory("host_inventory.json")
    analyzed_hosts = analyze_inventory(hosts)
    high_risk_hosts = get_high_risk_hosts(analyzed_hosts, threshold=50)

    json_report = generate_json_report(analyzed_hosts, high_risk_hosts)
    text_summary = generate_text_summary(analyzed_hosts, high_risk_hosts)
    html_report = generate_html_report(analyzed_hosts)

    with open("high_risk_report.json", "w", encoding="utf-8") as file:
        json.dump(json_report, file, indent=2)

    with open("patch_summary.txt", "w", encoding="utf-8") as file:
        file.write(text_summary)

    with open("patch_report.html", "w", encoding="utf-8") as file:
        file.write(html_report)

    print("Patch analysis complete.")
    print(f"Total hosts analyzed: {len(analyzed_hosts)}")
    print(f"High-risk hosts found: {len(high_risk_hosts)}")
    print("Generated files:")
    print("- high_risk_report.json")
    print("- patch_summary.txt")
    print("- patch_report.html")


if __name__ == "__main__":
    main()