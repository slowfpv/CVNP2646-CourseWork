# Week 10 - User Account & Permissions Auditor

## Overview
This project is a Python-based IAM auditing tool that loads user account data and role membership data, joins them using `user_id`, detects policy violations, and generates compliance reports in both JSON and text formats.

IAM auditing is important because compromised credentials, orphaned accounts, stale accounts, and excessive permissions are common causes of security incidents. This tool supports regular access reviews and helps identify violations before an audit.

## Usage
Run the program with:

```bash
python3 permissions_auditor.py
