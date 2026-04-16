import json
import random
from datetime import datetime, timedelta

random.seed(42)

departments = {
    "Finance": ["pci-scope"],
    "HR": ["hipaa"],
    "Engineering": [],
    "IT": [],
    "Operations": [],
    "Security": []
}

os_profiles = [
    # Windows
    ("Windows 11 Pro", "23H2"),
    ("Windows 10 Pro", "22H2"),
    ("Windows Server 2019", "2019"),
    ("Windows Server 2022", "2022"),

    # Linux (enterprise + school)
    ("Ubuntu 22.04", "22.04"),
    ("Ubuntu 20.04", "20.04"),
    ("Red Hat Enterprise Linux", "9"),
    ("Red Hat Enterprise Linux", "8"),
    ("CentOS 7", "7"),
    ("Debian 11", "11"),

    # School / ATCC-style systems
    ("ATCC Linux Server", "custom"),
    ("ATCC Lab Linux", "edu"),

    # macOS
    ("macOS Ventura", "13"),
    ("macOS Sonoma", "14")
]

roles = [
    "WEB", "DB", "APP", "DC", "FIN", "HR", "DEV", "OPS", "SEC", "API"
]

def weighted_choice(options):
    values = [item[0] for item in options]
    weights = [item[1] for item in options]
    return random.choices(values, weights=weights, k=1)[0]

def make_hostname(role, index, environment):
    env_code = {
        "production": "PRD",
        "staging": "STG",
        "development": "DEV"
    }[environment]
    return f"{role}-{env_code}-{index:03d}"

def make_ip(index):
    third = (index // 250) + 10
    fourth = (index % 250) + 1
    return f"10.20.{third}.{fourth}"

def build_host(index):
    environment = weighted_choice([
        ("production", 55),
        ("staging", 20),
        ("development", 25)
    ])

    department = weighted_choice([
        ("IT", 20),
        ("Engineering", 20),
        ("Finance", 15),
        ("HR", 10),
        ("Operations", 20),
        ("Security", 15)
    ])

    role = weighted_choice([
        ("WEB", 15),
        ("DB", 12),
        ("APP", 18),
        ("DC", 5),
        ("FIN", 10),
        ("HR", 8),
        ("DEV", 15),
        ("OPS", 10),
        ("SEC", 4),
        ("API", 3)
    ])

    os_name, os_version = random.choice(os_profiles)

    if environment == "production":
        criticality = weighted_choice([
            ("critical", 25),
            ("high", 40),
            ("medium", 25),
            ("low", 10)
        ])
        patch_days = random.randint(10, 180)
    elif environment == "staging":
        criticality = weighted_choice([
            ("critical", 5),
            ("high", 25),
            ("medium", 45),
            ("low", 25)
        ])
        patch_days = random.randint(5, 120)
    else:
        criticality = weighted_choice([
            ("critical", 2),
            ("high", 10),
            ("medium", 38),
            ("low", 50)
        ])
        patch_days = random.randint(1, 90)

    tags = set(departments[department])

    if role == "WEB":
        tags.add("internet-facing")
    if role == "API" and environment != "development":
        tags.add("internet-facing")
    if role == "DC":
        tags.add("tier-0")
    if department == "Security" and random.random() < 0.4:
        tags.add("internet-facing")
    if department == "Finance" and environment == "production":
        tags.add("pci-scope")
    if department == "HR" and environment == "production":
        tags.add("hipaa")
    if role == "DB" and random.random() < 0.25:
        tags.add("backup-critical")

    last_patch_date = (datetime.now() - timedelta(days=patch_days)).strftime("%Y-%m-%d")

    hostname = make_hostname(role, index, environment)

    return {
        "hostname": hostname,
        "ip_address": make_ip(index),
        "os": os_name,
        "os_version": os_version,
        "last_patch_date": last_patch_date,
        "criticality": criticality,
        "environment": environment,
        "department": department,
        "owner": f"{department.lower()}.{index}@company.com",
        "tags": sorted(tags)
    }

def main():
    hosts = [build_host(i) for i in range(1, 101)]

    # Add a few intentionally bad systems so the report has obvious top risks
    hosts[0]["hostname"] = "WEB-PRD-001"
    hosts[0]["criticality"] = "critical"
    hosts[0]["environment"] = "production"
    hosts[0]["department"] = "Finance"
    hosts[0]["last_patch_date"] = (datetime.now() - timedelta(days=160)).strftime("%Y-%m-%d")
    hosts[0]["tags"] = ["internet-facing", "pci-scope"]

    hosts[1]["hostname"] = "DC-PRD-002"
    hosts[1]["criticality"] = "critical"
    hosts[1]["environment"] = "production"
    hosts[1]["department"] = "IT"
    hosts[1]["last_patch_date"] = (datetime.now() - timedelta(days=140)).strftime("%Y-%m-%d")
    hosts[1]["tags"] = ["tier-0"]

    hosts[2]["hostname"] = "HR-PRD-003"
    hosts[2]["criticality"] = "high"
    hosts[2]["environment"] = "production"
    hosts[2]["department"] = "HR"
    hosts[2]["last_patch_date"] = (datetime.now() - timedelta(days=120)).strftime("%Y-%m-%d")
    hosts[2]["tags"] = ["hipaa"]

    with open("host_inventory.json", "w", encoding="utf-8") as file:
        json.dump(hosts, file, indent=2)

    print("Realistic 100-host inventory generated in host_inventory.json")

if __name__ == "__main__":
    main()