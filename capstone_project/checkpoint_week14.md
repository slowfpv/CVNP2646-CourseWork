# Week 14 Implementation Checkpoint

## What Works

The MVP version of VulnPriority Pro runs from the command line and processes a real JSON input file. It reads vulnerability data from `data/vulnerability_data.json`, creates Host and Vulnerability objects, calculates risk scores, and writes a JSON report and text summary report.

The tool also includes basic logging through Python's logging module. It creates a `vulnpriority.log` file and logs when the program starts, finishes, or fails.

## What's Missing

The current version does not have unit tests yet. Those will be added during Week 15. The tool also has basic error handling, but it can be improved by adding more detailed input validation for missing fields and bad data types.

Nice-to-have features like CSV export, MITRE ATT&CK notes, and filtering only internet-facing systems are not implemented yet.

## Changes from Proposal

The main design stayed close to the original proposal. I kept the Vulnerability, Host, RiskAnalyzer, and ReportGenerator classes. The only change is that I kept the MVP simple so it could run end-to-end first.

## AI Usage

I used ChatGPT to help organize the MVP structure and create a simple version of the code. I accepted the idea of separating the project into classes because it matched the assignment requirements. I reviewed the code and kept the logic simple enough that I can explain how it works.

