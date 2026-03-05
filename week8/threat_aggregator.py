#!/usr/bin/env python3
"""
CVNP2646 - Threat Intelligence Aggregator
Loads 3 JSON feeds with different schemas, normalizes indicators,
validates, deduplicates, filters, and outputs 3 formats:
- firewall_blocklist.json
- siem_feed.json
- summary_report.txt
"""

import json
from datetime import datetime
from collections import Counter


# -------------------------
# Load & Parse
# -------------------------
def load_json(filepath):
    """Safely load JSON from a file. Returns dict or None."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"ERROR: Missing file: {filepath}")
        return None
    except json.JSONDecodeError as e:
        print(f"ERROR: Malformed JSON in {filepath}: {e}")
        return None


def extract_raw_indicators(feed_data):
    """
    Extract vendor indicators regardless of schema.
    Returns a list of raw indicator dicts.
    """
    if not isinstance(feed_data, dict):
        return []

    # VendorA style
    if isinstance(feed_data.get("indicators"), list):
        return feed_data["indicators"]

    # VendorB style
    if isinstance(feed_data.get("feed"), list):
        return feed_data["feed"]

    # VendorC style
    if isinstance(feed_data.get("items"), list):
        return feed_data["items"]

    return []


# -------------------------
# Normalize
# -------------------------
def normalize_indicator(raw, source_name):
    """
    Convert any vendor raw indicator into a standard format using .get() fallbacks.
    Standard format keys:
      id, type, value, confidence, threat_level, first_seen, sources
    """
    # Different vendors call these different names:
    _id = raw.get("id") or raw.get("ioc_id") or raw.get("ref")
    _type = raw.get("type") or raw.get("indicator_type") or raw.get("category")
    _value = raw.get("value") or raw.get("indicator_value") or raw.get("ioc")
    _confidence = raw.get("confidence")
    if _confidence is None:
        _confidence = raw.get("score")
    if _confidence is None:
        _confidence = raw.get("reliability")

    _threat = raw.get("threat") or raw.get("severity") or raw.get("risk")
    _seen = raw.get("first_seen") or raw.get("seen") or raw.get("date")

    # ensure sources is always a list (critical for dedup merges)
    return {
        "id": _id,
        "type": _type,
        "value": _value,
        "confidence": _confidence,
        "threat_level": _threat,
        "first_seen": _seen,
        "sources": [source_name]
    }


# -------------------------
# Validate
# -------------------------
VALID_TYPES = {"ip", "domain", "hash", "url"}
VALID_LEVELS = {"low", "medium", "high", "critical"}


def validate_indicators(indicators):
    """
    Validate normalized indicators.
    Returns: (valid_list, error_count, error_messages)
    """
    valid = []
    errors = []

    for idx, ind in enumerate(indicators):
        # Required fields must exist and be usable
        for field in ["id", "type", "value", "confidence", "threat_level"]:
            if field not in ind or ind[field] is None:
                errors.append(f"Indicator {idx}: missing required field '{field}'")
                break
        else:
            # Type checks + value checks
            if not isinstance(ind["value"], str) or ind["value"].strip() == "":
                errors.append(f"Indicator {idx}: 'value' must be a non-empty string")
                continue

            ind["value"] = ind["value"].strip()

            if ind["type"] not in VALID_TYPES:
                errors.append(f"Indicator {idx}: invalid type '{ind['type']}'")
                continue

            if not isinstance(ind["confidence"], (int, float)):
                errors.append(f"Indicator {idx}: confidence must be numeric")
                continue

            if not (0 <= ind["confidence"] <= 100):
                errors.append(f"Indicator {idx}: confidence out of range (0-100)")
                continue

            if ind["threat_level"] not in VALID_LEVELS:
                errors.append(f"Indicator {idx}: invalid threat_level '{ind['threat_level']}'")
                continue

            # sources must be list
            if not isinstance(ind.get("sources"), list):
                errors.append(f"Indicator {idx}: sources must be a list")
                continue

            valid.append(ind)

    return valid, len(errors), errors


# -------------------------
# Deduplicate
# -------------------------
def deduplicate_indicators(indicators):
    """
    Dedupe using key (type, value).
    Keep highest confidence.
    Merge sources lists.
    Returns: (unique_list, duplicates_removed_count)
    """
    unique = {}
    dup_count = 0

    for ind in indicators:
        key = (ind["type"], ind["value"])

        if key not in unique:
            unique[key] = ind
            continue

        dup_count += 1
        existing = unique[key]

        # merge sources (avoid duplicates)
        merged_sources = list(set(existing["sources"] + ind["sources"]))

        # keep highest confidence indicator
        if ind["confidence"] > existing["confidence"]:
            ind["sources"] = merged_sources
            unique[key] = ind
        else:
            existing["sources"] = merged_sources
            unique[key] = existing

    return list(unique.values()), dup_count


# -------------------------
# Filter
# -------------------------
def filter_indicators(indicators, min_conf=85, levels=None, types=None):
    if levels is None:
        levels = ["high", "critical"]
    if types is None:
        types = ["ip", "domain"]

    return [
        ind for ind in indicators
        if ind["confidence"] >= min_conf
        and ind["threat_level"] in levels
        and ind["type"] in types
    ]


# -------------------------
# Transform Outputs
# -------------------------
def transform_to_firewall(indicators):
    entries = []
    for ind in indicators:
        entries.append({
            "address": ind["value"],
            "type": ind["type"],
            "action": "block",
            "priority": "high" if ind["threat_level"] == "critical" else "medium",
            "reason": f"{ind['threat_level']} threat, confidence {ind['confidence']}%",
            "sources": ind["sources"]
        })

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "total_entries": len(entries),
        "blocklist": entries
    }


def transform_to_siem(indicators):
    events = []
    for ind in indicators:
        events.append({
            "ioc_type": ind["type"],
            "ioc_value": ind["value"],
            "confidence": ind["confidence"],
            "severity": ind["threat_level"],
            "first_seen": ind.get("first_seen"),
            "sources": ind["sources"]
        })

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "format": "SIEM_FEED",
        "count": len(events),
        "events": events
    }


def build_text_summary(stats):
    lines = []
    lines.append("=" * 70)
    lines.append("THREAT INTELLIGENCE AGGREGATOR - SUMMARY REPORT")
    lines.append("=" * 70)
    lines.append(f"Generated At: {stats['generated_at']}")
    lines.append("")
    lines.append("PIPELINE COUNTS")
    lines.append("-" * 70)
    lines.append(f"Total Loaded:        {stats['total_loaded']}")
    lines.append(f"Valid Indicators:    {stats['valid_count']}")
    lines.append(f"Unique (Deduped):    {stats['unique_count']}")
    lines.append(f"Filtered Output:     {stats['filtered_count']}")
    lines.append(f"Duplicates Removed:  {stats['duplicates_removed']}")
    lines.append("")
    lines.append("DISTRIBUTIONS (Filtered)")
    lines.append("-" * 70)
    lines.append(f"By Type:     {stats['type_distribution']}")
    lines.append(f"By Severity: {stats['severity_distribution']}")
    lines.append("")
    lines.append("SOURCE CONTRIBUTION (Unique Indicators)")
    lines.append("-" * 70)
    for k, v in stats["source_contribution"].items():
        lines.append(f"{k}: {v}")

    lines.append("=" * 70)
    return "\n".join(lines)


# -------------------------
# Statistics
# -------------------------
def generate_statistics(total_loaded, valid_list, unique_list, filtered_list):
    type_counts = Counter(ind["type"] for ind in filtered_list)
    severity_counts = Counter(ind["threat_level"] for ind in filtered_list)

    source_counts = Counter()
    for ind in unique_list:
        for s in ind["sources"]:
            source_counts[s] += 1

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "total_loaded": total_loaded,
        "valid_count": len(valid_list),
        "unique_count": len(unique_list),
        "filtered_count": len(filtered_list),
        "duplicates_removed": total_loaded - len(unique_list),
        "type_distribution": dict(type_counts),
        "severity_distribution": dict(severity_counts),
        "source_contribution": dict(source_counts)
    }


# -------------------------
# Main Pipeline
# -------------------------
def write_json(filepath, data):
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def write_text(filepath, text):
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(text)


def main():
    feeds = [
        ("vendor_a.json", "VendorA"),
        ("vendor_b.json", "VendorB"),
        ("vendor_c.json", "VendorC"),
    ]

    normalized_all = []
    total_loaded = 0

    for path, source in feeds:
        data = load_json(path)
        if data is None:
            continue

        raw_list = extract_raw_indicators(data)
        total_loaded += len(raw_list)

        for raw in raw_list:
            normalized_all.append(normalize_indicator(raw, source))

    valid_list, error_count, error_messages = validate_indicators(normalized_all)

    unique_list, dup_count = deduplicate_indicators(valid_list)

    filtered_list = filter_indicators(unique_list, min_conf=85, levels=["high", "critical"], types=["ip", "domain"])

    firewall_out = transform_to_firewall(filtered_list)
    siem_out = transform_to_siem(filtered_list)

    stats = generate_statistics(total_loaded, valid_list, unique_list, filtered_list)
    summary_txt = build_text_summary(stats)

    write_json("firewall_blocklist.json", firewall_out)
    write_json("siem_feed.json", siem_out)
    write_text("summary_report.txt", summary_txt)

    # Console output (useful for video)
    print("=" * 70)
    print("AGGREGATOR RUN COMPLETE")
    print("=" * 70)
    print(f"Loaded indicators:      {total_loaded}")
    print(f"Valid indicators:       {len(valid_list)}")
    print(f"Validation errors:      {error_count}")
    print(f"Duplicates removed:     {dup_count}")
    print(f"Filtered output count:  {len(filtered_list)}")
    print("-" * 70)
    if error_messages:
        print("Sample validation errors:")
        for msg in error_messages[:3]:
            print(f" - {msg}")
    print("-" * 70)
    print("Outputs created:")
    print(" - firewall_blocklist.json")
    print(" - siem_feed.json")
    print(" - summary_report.txt")


if __name__ == "__main__":
    main()