# VulnPriority Pro

VulnPriority Pro is a Python cybersecurity tool that prioritizes vulnerable systems based on CVSS score, system criticality, and internet-facing status.

## Problem Statement

Security teams often have many vulnerable systems to review. Manually checking every system can take too much time and may cause high-risk systems to be missed. This tool helps rank vulnerable hosts so analysts know which systems should be fixed first.

## Features

- Reads vulnerability data from a JSON file
- Validates required JSON fields
- Calculates risk scores for each host
- Labels hosts as Critical, High, Medium, or Low risk
- Sorts systems from highest risk to lowest risk
- Generates a JSON report
- Generates a text summary report
- Uses command-line arguments with argparse
- Uses logging for diagnostics
- Includes pytest unit tests

## Project Structure

```text
capstone_project/
├── README.md
├── requirements.txt
├── vulnpriority.log
├── data/
│   └── vulnerability_data.json
├── reports/
│   ├── risk_report.json
│   └── summary_report.txt
├── src/
│   ├── __init__.py
│   └── main.py
└── tests/
    └── test_main.py