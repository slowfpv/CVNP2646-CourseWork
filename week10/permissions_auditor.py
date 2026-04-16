import json
from datetime import datetime
from collections import defaultdict


AUDITOR_NAME = "IAM Audit System v1.0"


def load_json(filepath):
    """Load JSON data from a file and return a list of dictionaries."""
    with open(filepath, "r", encoding="utf-8") as file:
        return json.load(file)


def build_user_lookup(users_data):
    """Build a dictionary keyed by user_id for fast O(1) lookups."""
    return {user["user_id"]: user for user in users_data}


def group_roles_by_user(roles_data):
    """Group all roles by user_id using defaultdict(list)."""
    user_roles = defaultdict(list)
    for role_entry in roles_data:
        user_roles[role_entry["user_id"]].append(role_entry["role"])
    return dict(user_roles)


def check_disabled_with_roles(users_dict, roles_data):
    """Find disabled users who still have one or more assigned roles."""
    violations = []
    user_roles = group_roles_by_user(roles_data)
    users_with_roles = set(user_roles.keys())

    for user_id, user in users_dict.items():
        if user.get("status", "").lower() == "disabled" and user_id in users_with_roles:
            roles = user_roles.get(user_id, [])
            violations.append({
                "user_id": user_id,
                "username": user.get("username", "unknown"),
                "violation_type": "disabled_with_roles",
                "severity": "CRITICAL",
                "details": f"Disabled account has {len(roles)} active role(s): {', '.join(roles)}"
            })

    return violations


def check_unauthorized_admins(users_dict, roles_data, authorized_depts=None):
    """Find admin roles assigned to users outside authorized departments."""
    if authorized_depts is None:
        authorized_depts = {"IT", "Security"}

    violations = []

    for role_entry in roles_data:
        role = role_entry.get("role", "")
        user_id = role_entry.get("user_id", "")

        if "admin" in role.lower() and user_id in users_dict:
            user = users_dict[user_id]
            department = user.get("department", "")
            if department not in authorized_depts:
                violations.append({
                    "user_id": user_id,
                    "username": user.get("username", "unknown"),
                    "violation_type": "unauthorized_admin",
                    "severity": "HIGH",
                    "details": f"User in {department} has admin role: {role}"
                })

    return violations


def check_stale_accounts(users_dict, stale_days=90):
    """Find active accounts with no login or last login older than stale_days."""
    violations = []

    for user_id, user in users_dict.items():
        if user.get("status", "").lower() != "active":
            continue

        last_login = user.get("last_login", "").strip()

        if not last_login:
            violations.append({
                "user_id": user_id,
                "username": user.get("username", "unknown"),
                "violation_type": "stale_account",
                "severity": "MEDIUM",
                "details": "Active account has no recorded last_login value"
            })
            continue

        login_date = datetime.strptime(last_login, "%Y-%m-%d")
        days_since_login = (datetime.now() - login_date).days

        if days_since_login > stale_days:
            violations.append({
                "user_id": user_id,
                "username": user.get("username", "unknown"),
                "violation_type": "stale_account",
                "severity": "MEDIUM",
                "details": f"Active account has not logged in for {days_since_login} days"
            })

    return violations


def check_conflicting_roles(users_dict, roles_data):
    """Detect separation-of-duties violations such as admin + auditor."""
    violations = []
    user_roles = group_roles_by_user(roles_data)

    for user_id, roles in user_roles.items():
        role_set = {role.lower() for role in roles}
        if "admin" in role_set and "auditor" in role_set and user_id in users_dict:
            user = users_dict[user_id]
            violations.append({
                "user_id": user_id,
                "username": user.get("username", "unknown"),
                "violation_type": "conflicting_roles",
                "severity": "CRITICAL",
                "details": "User has conflicting roles: admin and auditor"
            })

    return violations


def check_excessive_permissions(users_dict, roles_data, threshold=5):
    """Detect users with too many roles, indicating privilege creep."""
    violations = []
    user_roles = group_roles_by_user(roles_data)

    for user_id, roles in user_roles.items():
        if len(roles) > threshold and user_id in users_dict:
            user = users_dict[user_id]
            violations.append({
                "user_id": user_id,
                "username": user.get("username", "unknown"),
                "violation_type": "excessive_permissions",
                "severity": "MEDIUM",
                "details": f"User has {len(roles)} assigned roles, exceeding threshold of {threshold}"
            })

    return violations


def check_orphaned_roles(users_dict, roles_data):
    """Detect role assignments that reference a user_id not present in users data."""
    violations = []
    valid_user_ids = set(users_dict.keys())

    for role_entry in roles_data:
        user_id = role_entry.get("user_id", "")
        if user_id not in valid_user_ids:
            violations.append({
                "user_id": user_id,
                "username": "unknown",
                "violation_type": "orphaned_role",
                "severity": "HIGH",
                "details": f"Role assignment exists for unknown user_id: {user_id} ({role_entry.get('role', 'unknown role')})"
            })

    return violations


def check_unapproved_departments(users_dict, approved_departments=None):
    """Detect users assigned to departments outside the approved list."""
    if approved_departments is None:
        approved_departments = {"IT", "Security", "Finance", "HR", "Marketing"}

    violations = []

    for user_id, user in users_dict.items():
        department = user.get("department", "")
        if department not in approved_departments:
            violations.append({
                "user_id": user_id,
                "username": user.get("username", "unknown"),
                "violation_type": "unapproved_department",
                "severity": "LOW",
                "details": f"User belongs to unapproved department: {department}"
            })

    return violations


def generate_json_report(all_violations, users_dict, roles_data):
    """Generate structured JSON report for automation and SIEM use."""
    by_severity = defaultdict(int)
    by_type = defaultdict(int)

    for violation in all_violations:
        by_severity[violation["severity"]] += 1
        by_type[violation["violation_type"]] += 1

    report = {
        "audit_metadata": {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "total_users_audited": len(users_dict),
            "total_role_assignments": len(roles_data),
            "total_violations": len(all_violations),
            "auditor": AUDITOR_NAME
        },
        "violation_summary": {
            "by_severity": {
                "CRITICAL": by_severity["CRITICAL"],
                "HIGH": by_severity["HIGH"],
                "MEDIUM": by_severity["MEDIUM"],
                "LOW": by_severity["LOW"]
            },
            "by_type": dict(sorted(by_type.items()))
        },
        "all_violations": all_violations
    }

    return report


def generate_text_report(all_violations, users_dict, roles_data):
    """Generate management-friendly text report."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    by_severity = defaultdict(int)
    by_type = defaultdict(int)
    grouped_by_severity = defaultdict(list)

    for violation in all_violations:
        by_severity[violation["severity"]] += 1
        by_type[violation["violation_type"]] += 1
        grouped_by_severity[violation["severity"]].append(violation)

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    lines = []
    lines.append("=" * 80)
    lines.append("USER ACCOUNT & PERMISSIONS AUDIT REPORT")
    lines.append("=" * 80)
    lines.append(f"Generated: {timestamp}")
    lines.append(f"Auditor: {AUDITOR_NAME}")
    lines.append("")
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 80)
    lines.append(f"Total Users Audited: {len(users_dict)}")
    lines.append(f"Total Role Assignments: {len(roles_data)}")
    lines.append(f"Total Violations Found: {len(all_violations)}")
    lines.append("")
    lines.append("VIOLATIONS BY SEVERITY")
    lines.append("-" * 80)

    for severity in severity_order:
        count = by_severity[severity]
        bar = "█" * count
        lines.append(f"{severity:<12} [{count:>3}] {bar}")

    lines.append("")
    lines.append("VIOLATIONS BY TYPE")
    lines.append("-" * 80)

    for violation_type, count in sorted(by_type.items(), key=lambda item: item[1], reverse=True):
        lines.append(f"{violation_type:<35} {count}")

    lines.append("")
    lines.append("DETAILED VIOLATIONS")
    lines.append("=" * 80)
    lines.append("")

    for severity in severity_order:
        issues = grouped_by_severity[severity]
        if not issues:
            continue

        lines.append(f"{severity} SEVERITY ({len(issues)} issues)")
        lines.append("-" * 80)
        lines.append("")

        for index, issue in enumerate(issues, start=1):
            lines.append(f"{index}. User: {issue['username']} (ID: {issue['user_id']})")
            lines.append(f"   Type: {issue['violation_type']}")
            lines.append(f"   Details: {issue['details']}")
            lines.append("")

    lines.append("=" * 80)
    lines.append("END OF REPORT")
    lines.append("=" * 80)

    return "\n".join(lines)


def main():
    """Run the IAM audit pipeline end to end."""
    users_data = load_json("users.json")
    roles_data = load_json("roles.json")

    users_dict = build_user_lookup(users_data)

    all_violations = []
    all_violations.extend(check_disabled_with_roles(users_dict, roles_data))
    all_violations.extend(check_unauthorized_admins(users_dict, roles_data))
    all_violations.extend(check_stale_accounts(users_dict))
    all_violations.extend(check_conflicting_roles(users_dict, roles_data))
    all_violations.extend(check_excessive_permissions(users_dict, roles_data))
    all_violations.extend(check_orphaned_roles(users_dict, roles_data))
    all_violations.extend(check_unapproved_departments(users_dict))

    json_report = generate_json_report(all_violations, users_dict, roles_data)
    text_report = generate_text_report(all_violations, users_dict, roles_data)

    with open("audit_report.json", "w", encoding="utf-8") as file:
        json.dump(json_report, file, indent=2)

    with open("audit_report.txt", "w", encoding="utf-8") as file:
        file.write(text_report)

    print(f"Audit complete! Found {len(all_violations)} violations.")
    print("Reports saved: audit_report.json, audit_report.txt")


if __name__ == "__main__":
    main()
