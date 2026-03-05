#!/usr/bin/env python3

#CVNP2646 - Week 7 Project

#Reads a JSON backup plan, validates it (4 levels), and simulates a backup
#without touching the real filesystem. Generates a readable dry-run report.


import json
import sys
import random
from datetime import datetime


# -----------------------------
# Part 1: Load Config
# -----------------------------
def load_config(filepath):
    """
    Load and parse a JSON configuration file.

    Returns:
        dict config on success, or None on error
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"ERROR: Config file not found: {filepath}")
        return None
    except json.JSONDecodeError as e:
        print(f"ERROR: JSON syntax error in '{filepath}': {e}")
        return None
    except Exception as e:
        print(f"ERROR: Unexpected error loading config '{filepath}': {e}")
        return None


# -----------------------------
# Part 2: Validate Config (4 levels)
# -----------------------------
def validate_config(config):
    """
    Validate config across 4 levels:
      1) Structure (already parsed; this function expects dict)
      2) Required fields
      3) Type validation
      4) Value validation

    Returns:
        (is_valid: bool, errors: list[str])
    """
    errors = []

    # Level 1: Structure validation (we assume load_config handled file + parsing)
    if config is None:
        return False, ["Config is None (failed to load)."]

    if not isinstance(config, dict):
        return False, [f"Config must be a JSON object/dict, got {type(config).__name__}"]

    # Level 2: Required fields
    required_top = ["plan_name", "sources", "destination"]
    for field in required_top:
        if field not in config:
            errors.append(f"Missing required field: '{field}'")

    # If missing critical top-level fields, still continue collecting errors safely
    plan_name = config.get("plan_name")
    sources = config.get("sources")
    destination = config.get("destination")

    # Level 3: Type validation
    if "plan_name" in config and not isinstance(plan_name, str):
        errors.append(f"'plan_name' must be a string, got {type(plan_name).__name__}")

    if "version" in config and not isinstance(config["version"], str):
        errors.append(f"'version' must be a string, got {type(config['version']).__name__}")

    if "created_by" in config and not isinstance(config["created_by"], str):
        errors.append(f"'created_by' must be a string, got {type(config['created_by']).__name__}")

    if "description" in config and not isinstance(config["description"], str):
        errors.append(f"'description' must be a string, got {type(config['description']).__name__}")

    if "sources" in config and not isinstance(sources, list):
        errors.append(f"'sources' must be a list, got {type(sources).__name__}")

    if "destination" in config and not isinstance(destination, dict):
        errors.append(f"'destination' must be an object/dict, got {type(destination).__name__}")

    if "options" in config and not isinstance(config["options"], dict):
        errors.append(f"'options' must be an object/dict, got {type(config['options']).__name__}")

    # Level 4: Value validation (only if the types are usable)
    if isinstance(plan_name, str) and plan_name.strip() == "":
        errors.append("'plan_name' cannot be empty")

    # Validate sources list contents
    if isinstance(sources, list):
        if len(sources) == 0:
            errors.append("'sources' list cannot be empty")

        for i, src in enumerate(sources):
            if not isinstance(src, dict):
                errors.append(f"Source {i}: must be an object/dict, got {type(src).__name__}")
                continue

            # required fields per source
            for req in ["name", "path", "recursive"]:
                if req not in src:
                    errors.append(f"Source {i}: missing '{req}' field")

            # name
            if "name" in src and not isinstance(src["name"], str):
                errors.append(f"Source {i}: 'name' must be a string, got {type(src['name']).__name__}")
            elif "name" in src and isinstance(src["name"], str) and src["name"].strip() == "":
                errors.append(f"Source {i}: 'name' cannot be empty")

            # path
            if "path" in src and not isinstance(src["path"], str):
                errors.append(f"Source {i}: 'path' must be a string, got {type(src['path']).__name__}")
            elif "path" in src and isinstance(src["path"], str) and src["path"].strip() == "":
                errors.append(f"Source {i}: 'path' cannot be empty")

            # recursive
            if "recursive" in src and not isinstance(src["recursive"], bool):
                errors.append(
                    f"Source {i}: 'recursive' must be a boolean, got {type(src['recursive']).__name__}"
                )

            # include/exclude patterns must be lists if present
            for patt_field in ["include_patterns", "exclude_patterns"]:
                if patt_field in src and not isinstance(src[patt_field], list):
                    errors.append(
                        f"Source {i}: '{patt_field}' must be a list, got {type(src[patt_field]).__name__}"
                    )
                # If list, ensure elements are strings
                if isinstance(src.get(patt_field), list):
                    for j, item in enumerate(src[patt_field]):
                        if not isinstance(item, str):
                            errors.append(
                                f"Source {i}: '{patt_field}[{j}]' must be a string, got {type(item).__name__}"
                            )

    # destination checks
    if isinstance(destination, dict):
        if "base_path" not in destination:
            errors.append("Missing required field: 'destination.base_path'")
        else:
            if not isinstance(destination["base_path"], str):
                errors.append(
                    f"'destination.base_path' must be a string, got {type(destination['base_path']).__name__}"
                )
            elif destination["base_path"].strip() == "":
                errors.append("'destination.base_path' cannot be empty")

        if "create_timestamped_folders" in destination and not isinstance(
            destination["create_timestamped_folders"], bool
        ):
            errors.append(
                f"'destination.create_timestamped_folders' must be a boolean, got {type(destination['create_timestamped_folders']).__name__}"
            )

        if "retention_days" in destination and not isinstance(destination["retention_days"], (int, float)):
            errors.append(
                f"'destination.retention_days' must be a number, got {type(destination['retention_days']).__name__}"
            )

    # options checks
    opts = config.get("options")
    if isinstance(opts, dict):
        if "verify_backups" in opts and not isinstance(opts["verify_backups"], bool):
            errors.append(
                f"'options.verify_backups' must be a boolean, got {type(opts['verify_backups']).__name__}"
            )
        if "max_file_size_mb" in opts and not isinstance(opts["max_file_size_mb"], (int, float)):
            errors.append(
                f"'options.max_file_size_mb' must be a number, got {type(opts['max_file_size_mb']).__name__}"
            )
        if isinstance(opts.get("max_file_size_mb"), (int, float)) and opts["max_file_size_mb"] <= 0:
            errors.append("'options.max_file_size_mb' must be > 0")

    return (len(errors) == 0), errors


# -----------------------------
# Part 3: Simulate Backup (DRY-RUN)
# -----------------------------
def _make_fake_filename(source_name, include_patterns):
    """
    Generate a realistic fake filename based on patterns.
    This does NOT check the filesystem.
    """
    # Some realistic "security log" name pools
    base_pool = [
        "firewall", "auth", "ids", "suricata", "apache_access", "apache_error",
        "ssh", "vpn", "waf", "dns", "proxy", "endpoint", "audit", "syslog"
    ]

    date_tag = datetime.now().strftime("%Y-%m-%d")
    time_tag = datetime.now().strftime("%H%M%S")

    # Pick an extension based on include_patterns if it looks like "*.log" etc
    ext_choices = []
    if isinstance(include_patterns, list):
        for p in include_patterns:
            p = p.strip()
            if p.startswith("*.") and len(p) > 2:
                ext_choices.append(p[1:])  # ".log"
            elif p.endswith(".log") or p.endswith(".txt") or p.endswith(".json"):
                # exact name patterns like "fast.log" or "eve.json"
                return p

    ext = random.choice(ext_choices) if ext_choices else ".log"

    base = random.choice(base_pool)
    # Sometimes include source name hint
    if random.random() < 0.35 and isinstance(source_name, str) and source_name.strip():
        base = source_name.lower().replace(" ", "_")

    styles = [
        f"{base}_{date_tag}{ext}",
        f"{base}_{date_tag}_{time_tag}{ext}",
        f"{base}_events_{date_tag}{ext}",
        f"{base}_archive_{date_tag}{ext}",
        f"{base}{ext}",
    ]
    return random.choice(styles)


def simulate_backup(config):
    """
    Dry-run simulation of backup operations.
    Generates fake files (5-15 per source) with sizes (1-100 MB).
    Does not perform any real file operations.

    Returns:
        report dict
    """
    timestamp = datetime.now()
    ts_iso = timestamp.isoformat(timespec="seconds")
    ts_folder = timestamp.strftime("%Y-%m-%d_%H%M%S")

    destination = config.get("destination", {})
    base_path = destination.get("base_path", "/backup")
    create_ts = destination.get("create_timestamped_folders", True)

    final_destination = f"{base_path}/{ts_folder}" if create_ts else base_path

    report = {
        "plan_name": config.get("plan_name", "Unknown Plan"),
        "mode": "DRY-RUN",
        "timestamp": ts_iso,
        "destination": final_destination,
        "summary": {
            "total_sources": 0,
            "total_files": 0,
            "total_size_mb": 0.0
        },
        "operations": []
    }

    sources = config.get("sources", [])
    report["summary"]["total_sources"] = len(sources) if isinstance(sources, list) else 0

    max_size = None
    opts = config.get("options")
    if isinstance(opts, dict):
        if isinstance(opts.get("max_file_size_mb"), (int, float)):
            max_size = float(opts["max_file_size_mb"])

    total_files = 0
    total_size = 0.0

    if not isinstance(sources, list):
        return report

    for src in sources:
        if not isinstance(src, dict):
            continue

        include_patterns = src.get("include_patterns", [])
        exclude_patterns = src.get("exclude_patterns", [])

        # Create 5-15 fake files per source
        file_count = random.randint(5, 15)
        files = []

        for _ in range(file_count):
            name = _make_fake_filename(src.get("name", ""), include_patterns)
            size_mb = round(random.uniform(1, 100), 1)

            # Enforce optional max_file_size_mb by clipping (still simulation)
            if max_size is not None and size_mb > max_size:
                size_mb = round(max_size, 1)

            files.append({"name": name, "size_mb": size_mb})

        op = {
            "source_name": src.get("name", "Unknown Source"),
            "source_path": src.get("path", ""),
            "recursive": bool(src.get("recursive", False)),
            "include_patterns": include_patterns if isinstance(include_patterns, list) else [],
            "exclude_patterns": exclude_patterns if isinstance(exclude_patterns, list) else [],
            "files": files
        }

        report["operations"].append(op)
        total_files += len(files)
        total_size += sum(f["size_mb"] for f in files)

    report["summary"]["total_files"] = total_files
    report["summary"]["total_size_mb"] = round(total_size, 1)

    return report


# -----------------------------
# Part 4: Generate Human Report
# -----------------------------
def generate_report(report_data):
    """
    Produce a readable text report from report_data dict.
    Returns: string report
    """
    lines = []
    
    lines.append("              BACKUP PLAN DRY-RUN SIMULATION")
    

    lines.append(f"Plan: {report_data.get('plan_name', 'Unknown')}")
    lines.append("Mode: DRY-RUN (no files will be copied)")
    lines.append(f"Timestamp: {report_data.get('timestamp', '')}")
    lines.append("")

    lines.append("-" * 70)
    lines.append("SUMMARY STATISTICS")
    lines.append("-" * 70)
    summary = report_data.get("summary", {})
    lines.append(f"Total Sources:     {summary.get('total_sources', 0)}")
    lines.append(f"Total Files:       {summary.get('total_files', 0)}")
    lines.append(f"Total Size:        {summary.get('total_size_mb', 0.0)} MB")
    lines.append(f"Destination:       {report_data.get('destination', '')}")
    lines.append("")

    operations = report_data.get("operations", [])
    for idx, op in enumerate(operations, start=1):
        lines.append("-" * 70)
        lines.append(f"SOURCE {idx}: {op.get('source_name', 'Unknown')}")
        lines.append("- " * 70)
        lines.append(f"Path: {op.get('source_path', '')}")
        lines.append(f"Recursive: {'Yes' if op.get('recursive') else 'No'}")

        inc = op.get("include_patterns", [])
        exc = op.get("exclude_patterns", [])

        lines.append(f"Include Patterns: {', '.join(inc) if inc else '(none)'}")
        lines.append(f"Exclude Patterns: {', '.join(exc) if exc else '(none)'}")

        files = op.get("files", [])
        lines.append(f"Files Found: {len(files)}")
        lines.append("")
        lines.append("Sample Files:")

        # show up to 3 samples
        for f in files[:3]:
            lines.append(f"  → {f['name']} ({f['size_mb']} MB)")

        if len(files) > 3:
            lines.append(f"  ... and {len(files) - 3} more files")

        lines.append("")

    
    lines.append("This was a DRY-RUN simulation. No files were copied.")
    

    return "\n".join(lines)


# -----------------------------
# main() orchestrator
# -----------------------------
def main():
 
    if len(sys.argv) < 2:
        print("Usage: python backup_planner.py <config.json>")
        sys.exit(1)

    config_path = sys.argv[1]
    config = load_config(config_path)

    # If load fails, stop
    if config is None:
        sys.exit(1)

    is_valid, errors = validate_config(config)

    if not is_valid:
        print("=" * 70)
        print("CONFIG VALIDATION FAILED")
        print("=" * 70)
        for e in errors:
            print(f"- {e}")
        sys.exit(1)

    report_data = simulate_backup(config)
    report_text = generate_report(report_data)
    print(report_text)

    # Optional: save a report file for evidence/video
    try:
        with open("sample_report.txt", "w", encoding="utf-8") as f:
            f.write(report_text)
        print("\n✓ sample_report.txt created/updated")
    except Exception as e:
        print(f"\nWARNING: Could not write sample_report.txt: {e}")


if __name__ == "__main__":
    main()