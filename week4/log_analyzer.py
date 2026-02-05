#!/usr/bin/env python3
# log_analyzer.py

import json
from collections import Counter
from pathlib import Path


def parse_log_file(filename):

    log_entries = []

    with open(filename, "r", encoding="utf-8") as f:
        for line in f:

            if not line.strip():
                continue

            parts = line.strip().split()

            # date time action source_ip dest_ip port
            if len(parts) >= 6:
                log_entries.append({
                    "date": parts[0],
                    "time": parts[1],
                    "action": parts[2].upper(),
                    "source_ip": parts[3],
                    "dest_ip": parts[4],
                    "port": int(parts[5])
                })

    return log_entries


def analyze_logs(log_entries):

    allow_count = 0
    deny_count = 0

    denied_ips = set()
    denied_ports = []
    timestamps = []

    for entry in log_entries:

        if entry["action"] == "ALLOW":
            allow_count += 1

        elif entry["action"] == "DENY":
            deny_count += 1
            denied_ips.add(entry["source_ip"])
            denied_ports.append(entry["port"])

        timestamps.append(f"{entry['date']} {entry['time']}")

    port_counter = Counter(denied_ports)

    most_targeted_port = None
    most_targeted_count = 0

    if port_counter:
        most_targeted_port, most_targeted_count = port_counter.most_common(1)[0]

    first_timestamp = timestamps[0] if timestamps else "N/A"
    last_timestamp = timestamps[-1] if timestamps else "N/A"

    return {
        "total_entries": len(log_entries),
        "allow_count": allow_count,
        "deny_count": deny_count,
        "denied_source_ips": sorted(list(denied_ips)),
        "most_targeted_port": most_targeted_port,
        "most_targeted_count": most_targeted_count,
        "time_range": {
            "first": first_timestamp,
            "last": last_timestamp
        }
    }


def save_json_report(analysis, filename):

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=2)


def display_summary(analysis):

    print("=" * 70)
    print("FIREWALL LOG ANALYSIS SUMMARY")
    print("=" * 70)
    print()

    print(f"📊 Total Log Entries: {analysis['total_entries']}")
    print()

    print(f"✅ ALLOW actions: {analysis['allow_count']}")
    print(f"🚫 DENY actions: {analysis['deny_count']}")

    total = analysis["total_entries"]
    deny_pct = (analysis["deny_count"] / total * 100) if total > 0 else 0
    print(f"   ({deny_pct:.1f}% of traffic was denied)")
    print()

    print(f"🔒 Unique denied source IPs: {len(analysis['denied_source_ips'])}")
    print("   Blocked IPs:")
    for ip in analysis["denied_source_ips"]:
        print(f"     - {ip}")
    print()

    if analysis["most_targeted_port"] is not None:

        port = analysis["most_targeted_port"]
        count = analysis["most_targeted_count"]

        port_names = {
            22: "SSH",
            23: "Telnet",
            80: "HTTP",
            135: "RPC",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP"
        }

        port_name = port_names.get(port, "Unknown")

        print(f"🎯 Most targeted port: {port} ({port_name})")
        print(f"   Attacked {count} times")
        print()

    print("⏰ Time range:")
    print(f"   First entry: {analysis['time_range']['first']}")
    print(f"   Last entry:  {analysis['time_range']['last']}")
    print()
    print("=" * 70)


if __name__ == "__main__":

    print()
    print("=" * 70)
    print("FIREWALL LOG ANALYZER")
    print("=" * 70)
    print()

    # ALWAYS load firewall.log from the same folder as this script
    script_dir = Path(__file__).resolve().parent
    log_path = script_dir / "firewall.log"
    output_path = script_dir / "log_analysis.json"

    print("📖 Reading firewall.log...")

    if not log_path.exists():
        print("❌ firewall.log not found at:")
        print(log_path)
        raise SystemExit(1)

    # -------------------------
    # DEBUG: prove what Python is reading
    # -------------------------
    print("\n--- DEBUG ---")
    print("SCRIPT:", Path(__file__).resolve())
    print("CWD:", Path.cwd())
    print("LOG PATH:", log_path)
    print("LOG EXISTS:", log_path.exists())
    print("LOG SIZE BYTES:", log_path.stat().st_size)

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for i in range(3):
            line = f.readline()
            print(f"LINE {i+1} repr:", repr(line))
            print(f"LINE {i+1} split_len:", len(line.strip().split()))
    print("-------------\n")
    # -------------------------

    log_entries = parse_log_file(log_path)

    print(f"✓ Parsed {len(log_entries)} log entries")
    print()

    print("🔍 Analyzing firewall traffic patterns...")
    analysis = analyze_logs(log_entries)
    print("✓ Analysis complete")
    print()

    display_summary(analysis)

    print()
    print("💾 Saving analysis to log_analysis.json...")
    save_json_report(analysis, output_path)
    print("✓ JSON report saved successfully")
    print()
