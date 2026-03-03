#!/usr/bin/env python3
# Authentication Log Scanner - CVNP2646 Week 6
# Parses authentication logs in key=value format (timestamp is first 2 tokens).
# Detects brute force patterns by counting FAIL events per user and per IP.
# Generates incident_report.json and incident_report.txt for SOC analysts.

import json
import sys
from datetime import datetime
from pathlib import Path
from collections import Counter


def parse_auth_line(line):
    # Returns (record_dict, error_string_or_None)
    raw = line.strip()

    # Skip empty lines
    if not raw:
        return None, "empty"

    parts = raw.split()

    # Must have at least date + time for timestamp
    if len(parts) < 2:
        return None, "missing_timestamp"

    # Timestamp is first TWO tokens
    timestamp = parts[0] + " " + parts[1]
    record = {"timestamp": timestamp}

    # Remaining tokens are key=value pairs (some may be malformed)
    for token in parts[2:]:
        if "=" not in token:
            # skip malformed key=value token safely
            continue

        key, value = token.split("=", 1)  # split once so extra '=' doesn't crash
        key = key.strip()
        value = value.strip()

        if not key:
            continue

        record[key] = value

    return record, None


def scan_log_file(log_path):
    failures_per_user = Counter()
    failures_per_ip = Counter()

    total_events = 0
    total_success = 0
    total_fail = 0
    parse_errors = 0

    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            record, error = parse_auth_line(line)

            if error:
                # empty lines don't count as parse errors, but missing timestamp does
                if error != "empty":
                    parse_errors += 1
                continue

            total_events += 1

            status = record.get("status", "UNKNOWN").upper()
            user = record.get("user", "UNKNOWN")
            ip_addr = record.get("ip", "UNKNOWN")

            if status == "SUCCESS":
                total_success += 1
            elif status == "FAIL":
                total_fail += 1
                failures_per_user[user] += 1
                failures_per_ip[ip_addr] += 1
            else:
                # unknown status still counts as an event, but not success/fail
                pass

    failure_rate = (total_fail / total_events * 100) if total_events > 0 else 0

    return {
        "total_events": total_events,
        "total_success": total_success,
        "total_fail": total_fail,
        "failure_rate": round(failure_rate, 1),
        "parse_errors": parse_errors,
        "failures_per_user": failures_per_user,
        "failures_per_ip": failures_per_ip,
    }


def build_json_report(results, analyst):
    now_iso = datetime.now().isoformat(timespec="seconds")

    top_users = [
        {"username": user, "failed_attempts": count}
        for user, count in results["failures_per_user"].most_common(5)
    ]

    top_ips = [
        {"ip_address": ip, "failed_attempts": count}
        for ip, count in results["failures_per_ip"].most_common(5)
    ]

    return {
        "metadata": {
            "generated_at": now_iso,
            "analyst": analyst,
            "classification": "INTERNAL"
        },
        "summary": {
            "total_events": results["total_events"],
            "total_success": results["total_success"],
            "total_fail": results["total_fail"],
            "failure_rate": results["failure_rate"],
            "parse_errors": results["parse_errors"]
        },
        "top_targeted_users": top_users,
        "top_attacking_ips": top_ips
    }


def build_text_report(results, analyst):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    total_events = results["total_events"]
    total_success = results["total_success"]
    total_fail = results["total_fail"]
    failure_rate = results["failure_rate"]
    parse_errors = results["parse_errors"]

    success_rate = (total_success / total_events * 100) if total_events > 0 else 0

    lines = []
    lines.append("=" * 70)
    lines.append("            AUTHENTICATION FAILURE ANALYSIS REPORT")
    lines.append(f"            Generated: {now}")
    lines.append("=" * 70)
    lines.append("")

    if failure_rate >= 20.0:
        lines.append(f"ALERT: High failure rate detected: {failure_rate}% (baseline: 2-5%)")
        lines.append("Potential BRUTE FORCE ATTACK in progress.")
    else:
        lines.append(f"Status: Failure rate {failure_rate}% (baseline: 2-5%).")
    lines.append("")

    lines.append("-" * 70)
    lines.append("SUMMARY STATISTICS")
    lines.append("-" * 70)
    lines.append(f"Total Events:        {total_events}")
    lines.append(f"Successful Logins:   {total_success} ({success_rate:.1f}%)")
    lines.append(f"Failed Attempts:     {total_fail} ({failure_rate}%)")
    lines.append(f"Parse Errors:        {parse_errors}")
    lines.append("")

    lines.append("-" * 70)
    lines.append("TOP 5 TARGETED ACCOUNTS")
    lines.append("-" * 70)

    if results["failures_per_user"]:
        for i, (user, count) in enumerate(results["failures_per_user"].most_common(5), start=1):
            lines.append(f"{i}. {user:<18} {count} failed attempts")
    else:
        lines.append("No failed login attempts detected.")
    lines.append("")

    lines.append("-" * 70)
    lines.append("TOP 5 ATTACKING SOURCE IPs")
    lines.append("-" * 70)

    if results["failures_per_ip"]:
        for i, (ip, count) in enumerate(results["failures_per_ip"].most_common(5), start=1):
            lines.append(f"{i}. {ip:<18} {count} failed attempts")
    else:
        lines.append("No attacking IPs detected.")
    lines.append("")

    lines.append("=" * 70)
    lines.append(f"Report generated by: {analyst}")
    lines.append("=" * 70)

    return "\n".join(lines)


def write_reports(out_dir, json_report, text_report):
    json_path = Path(out_dir) / "incident_report.json"
    txt_path = Path(out_dir) / "incident_report.txt"

    with open(json_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(json_report, indent=2))

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(text_report)


def main():
    if len(sys.argv) < 2:
        print("Usage: python auth_scanner.py <logfile>")
        return 1

    log_file = Path(sys.argv[1]).expanduser()

    if not log_file.exists():
        print(f"ERROR: Log file not found: {log_file}")
        return 1

    analyst = "Bryan Gonzalez"

    results = scan_log_file(log_file)
    json_report = build_json_report(results, analyst)
    text_report = build_text_report(results, analyst)

    write_reports(log_file.parent, json_report, text_report)

    # Console output for video demo
    print("=" * 70)
    print("SCAN COMPLETE")
    print("=" * 70)
    print(f"Log File:       {log_file.name}")
    print(f"Total Events:   {results['total_events']}")
    print(f"Total Success:  {results['total_success']}")
    print(f"Total Fail:     {results['total_fail']}")
    print(f"Failure Rate:   {results['failure_rate']}%")
    print(f"Parse Errors:   {results['parse_errors']}")
    print("-" * 70)
    print("Top Targeted Users:")
    for user, count in results["failures_per_user"].most_common(5):
        print(f"  {user}: {count}")
    print("Top Attacking IPs:")
    for ip, count in results["failures_per_ip"].most_common(5):
        print(f"  {ip}: {count}")
    print("-" * 70)
    print("✓ incident_report.json created")
    print("✓ incident_report.txt created")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())