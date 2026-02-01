"""
cvss_reporter.py
Week 3 - CVSS Vulnerability Reporter

- Stores CVSS as float (0.0 to 10.0)
- Converts score to percentage
- Categorizes severity:
  CRITICAL: 9.0-10.0
  HIGH:     7.0-8.9
  MEDIUM:   4.0-6.9
  LOW:      0.1-3.9
  NONE:     0.0
- Prints a formatted vulnerability report using f-strings
"""

def get_severity(score: float) -> str:
    """Return CVSS severity label based on score."""
    if score == 0.0:
        return "NONE"
    if 9.0 <= score <= 10.0:
        return "CRITICAL"
    if 7.0 <= score < 9.0:
        return "HIGH"
    if 4.0 <= score < 7.0:
        return "MEDIUM"
    if 0.1 <= score < 4.0:
        return "LOW"
    return "INVALID"


def cvss_to_percentage(score: float) -> float:
    """Convert CVSS score (0-10) to percentage (0-100)."""
    return (score / 10.0) * 100.0


def print_cvss_report(vuln_id: str, description: str, score: float) -> None:
    """Print a formatted CVSS report with decimal formatting."""
    severity = get_severity(score)
    percent = cvss_to_percentage(score)

    print("-" * 60)
    print("CVSS Vulnerability Report")
    print("-" * 60)
    print(f"Vulnerability ID:   {vuln_id}")
    print(f"Description:        {description}")
    print(f"CVSS Score:         {score:.1f} / 10.0")
    print(f"Score Percentage:   {percent:.2f}%")
    print(f"Severity Category:  {severity}")
    print("-" * 60)
    print()


def validate_score(score: float) -> bool:
    """Validate that score is within 0.0 to 10.0."""
    return 0.0 <= score <= 10.0


if __name__ == "__main__":
    # Required: test with at least 3 different CVSS scores (different severities)
    test_cases = [
        ("CVE-2026-0001", "Remote code execution in web service", 9.8),  # CRITICAL
        ("CVE-2026-0002", "Privilege escalation via misconfigured permissions", 6.5),  # MEDIUM
        ("CVE-2026-0003", "Information disclosure in verbose error messages", 2.7),  # LOW
    ]

    for vuln_id, desc, score in test_cases:
        if not validate_score(score):
            print(f"[ERROR] Invalid CVSS score: {score}. Must be 0.0 to 10.0")
            continue
        print_cvss_report(vuln_id, desc, score)
