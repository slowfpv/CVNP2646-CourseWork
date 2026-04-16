import json


def load_config(filepath):
    try:
        with open(filepath, "r") as file:
            return json.load(file)
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        return None


class DriftResult:
    CRITICAL_KEYWORDS = ["password", "secret", "admin", "root", "enabled"]

    def __init__(self, path, drift_type, baseline_value, current_value):
        self.path = path
        self.drift_type = drift_type
        self.baseline_value = baseline_value
        self.current_value = current_value
        self.severity = self._calculate_severity()

    def _calculate_severity(self):
        for keyword in self.CRITICAL_KEYWORDS:
            if keyword in self.path.lower():
                return "high"
        if self.drift_type == "missing":
            return "medium"
        return "low"

    def __str__(self):
        icons = {"missing": "[-]", "extra": "[+]", "changed": "[~]"}
        return f"{icons[self.drift_type]} {self.path} ({self.severity})"

    def to_dict(self):
        return {
            "path": self.path,
            "type": self.drift_type,
            "baseline": self.baseline_value,
            "current": self.current_value,
            "severity": self.severity
        }


def compare_configs(baseline, current, path=""):
    results = []

    if isinstance(baseline, dict) and isinstance(current, dict):
        b_keys = set(baseline.keys())
        c_keys = set(current.keys())

        for key in b_keys - c_keys:
            full = f"{path}.{key}" if path else key
            results.append(DriftResult(full, "missing", baseline[key], None))

        for key in c_keys - b_keys:
            full = f"{path}.{key}" if path else key
            results.append(DriftResult(full, "extra", None, current[key]))

        for key in b_keys & c_keys:
            full = f"{path}.{key}" if path else key
            results.extend(compare_configs(baseline[key], current[key], full))

    elif isinstance(baseline, list) and isinstance(current, list):
        max_len = max(len(baseline), len(current))
        for i in range(max_len):
            new_path = f"{path}[{i}]"

            if i >= len(baseline):
                results.append(DriftResult(new_path, "extra", None, current[i]))
            elif i >= len(current):
                results.append(DriftResult(new_path, "missing", baseline[i], None))
            else:
                results.extend(compare_configs(baseline[i], current[i], new_path))

    else:
        if baseline != current:
            results.append(DriftResult(path, "changed", baseline, current))

    return results


def display_report(results):
    print("\n=== DRIFT REPORT ===\n")

    for r in results:
        print(r)
        if r.drift_type == "changed":
            print(f"  baseline: {r.baseline_value}")
            print(f"  current:  {r.current_value}")


def main():
    baseline = load_config("baseline.json")
    current = load_config("current.json")

    if not baseline or not current:
        return

    results = compare_configs(baseline, current)
    display_report(results)


if __name__ == "__main__":
    main()
