import json
import pytest

from src.main import (
    Vulnerability,
    Host,
    RiskAnalyzer,
    build_hosts,
    validate_input_data,
    run_tool
)


def test_host_risk_score_critical_internet_facing():
    vuln = Vulnerability("CVE-2025-1234", 9.8, "Test vulnerability")
    host = Host("WEB-SRV-001", "10.0.0.10", "critical", True, [vuln])

    assert host.calculate_risk_score() == 100
    assert host.get_risk_level() == "Critical"


def test_host_with_no_vulnerabilities_has_zero_score():
    host = Host("DEV-WS-001", "10.0.0.30", "low", False, [])

    assert host.calculate_risk_score() == 0
    assert host.get_risk_level() == "Low"


def test_risk_analyzer_sorts_highest_risk_first():
    low_vuln = Vulnerability("CVE-LOW", 4.0, "Low issue")
    high_vuln = Vulnerability("CVE-HIGH", 9.5, "High issue")

    low_host = Host("LOW-HOST", "10.0.0.5", "low", False, [low_vuln])
    high_host = Host("HIGH-HOST", "10.0.0.10", "critical", True, [high_vuln])

    analyzer = RiskAnalyzer([low_host, high_host])
    results = analyzer.analyze("2026-04-27")

    assert results["top_priority_hosts"][0]["hostname"] == "HIGH-HOST"


def test_validate_input_missing_hosts_raises_error():
    bad_data = {
        "scan_date": "2026-04-27"
    }

    with pytest.raises(ValueError):
        validate_input_data(bad_data)


def test_validate_input_bad_cvss_raises_error():
    bad_data = {
        "scan_date": "2026-04-27",
        "hosts": [
            {
                "hostname": "BAD-HOST",
                "ip": "10.0.0.99",
                "criticality": "high",
                "internet_facing": False,
                "vulnerabilities": [
                    {
                        "cve": "CVE-BAD",
                        "cvss": "not-a-number",
                        "description": "Bad CVSS value"
                    }
                ]
            }
        ]
    }

    with pytest.raises(ValueError):
        validate_input_data(bad_data)


def test_build_hosts_creates_host_objects():
    data = {
        "scan_date": "2026-04-27",
        "hosts": [
            {
                "hostname": "WEB-SRV-001",
                "ip": "10.0.0.10",
                "criticality": "critical",
                "internet_facing": True,
                "vulnerabilities": [
                    {
                        "cve": "CVE-2025-1234",
                        "cvss": 9.8,
                        "description": "Remote code execution"
                    }
                ]
            }
        ]
    }

    hosts = build_hosts(data)

    assert len(hosts) == 1
    assert hosts[0].hostname == "WEB-SRV-001"
    assert len(hosts[0].vulnerabilities) == 1


def test_run_tool_creates_reports(tmp_path):
    input_file = tmp_path / "input.json"
    output_file = tmp_path / "risk_report.json"
    summary_file = tmp_path / "summary_report.txt"

    data = {
        "scan_date": "2026-04-27",
        "hosts": [
            {
                "hostname": "WEB-SRV-001",
                "ip": "10.0.0.10",
                "criticality": "critical",
                "internet_facing": True,
                "vulnerabilities": [
                    {
                        "cve": "CVE-2025-1234",
                        "cvss": 9.8,
                        "description": "Remote code execution"
                    }
                ]
            }
        ]
    }

    input_file.write_text(json.dumps(data))

    results = run_tool(str(input_file), str(output_file), str(summary_file))

    assert results["total_hosts"] == 1
    assert output_file.exists()
    assert summary_file.exists()
