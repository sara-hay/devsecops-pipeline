"""Policy-as-code gate: parse Semgrep + Trivy JSON output and fail the
build if any Critical-severity finding is present.
"""
import argparse
import json
import sys
from pathlib import Path

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# Semgrep's own severity field (ERROR/WARNING/INFO) is used only when a
# rule doesn't carry an explicit metadata.severity.
SEMGREP_SEVERITY_FALLBACK = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}


def load_json(path):
    file = Path(path)
    if not file.is_file():
        print(f"[security_gate] WARNING: {path} not found, skipping", file=sys.stderr)
        return None
    with file.open() as f:
        return json.load(f)


def count_semgrep(path, counts):
    data = load_json(path)
    if not data:
        return
    for result in data.get("results", []):
        extra = result.get("extra", {})
        severity = extra.get("metadata", {}).get("severity")
        if not severity:
            severity = SEMGREP_SEVERITY_FALLBACK.get(extra.get("severity", "").upper())
        severity = (severity or "").upper()
        if severity in counts:
            counts[severity] += 1


def count_trivy(path, counts):
    data = load_json(path)
    if not data:
        return
    for result in data.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            severity = (vuln.get("Severity") or "").upper()
            if severity in counts:
                counts[severity] += 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", default="semgrep-results.json")
    parser.add_argument("--trivy", default="trivy-results.json")
    args = parser.parse_args()

    counts = {severity: 0 for severity in SEVERITIES}
    count_semgrep(args.semgrep, counts)
    count_trivy(args.trivy, counts)

    print("Security scan summary:")
    for severity in SEVERITIES:
        print(f"  {severity:<8} {counts[severity]}")

    if counts["CRITICAL"] > 0:
        print(f"\n[security_gate] FAIL: {counts['CRITICAL']} Critical finding(s) found.")
        sys.exit(1)

    print("\n[security_gate] PASS: no Critical findings.")
    sys.exit(0)


if __name__ == "__main__":
    main()
