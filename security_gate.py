"""Policy-as-code gate: parse Semgrep + Trivy JSON output and fail the
build if any Critical-severity finding is present.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
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


def put_scan_metrics(table_name, region, repository, commit_hash, counts):
    import boto3

    table = boto3.resource("dynamodb", region_name=region).Table(table_name)
    table.put_item(
        Item={
            "CommitHash": commit_hash,
            "RepositoryName": repository,
            "Timestamp": datetime.now(timezone.utc).isoformat(),
            "CriticalCount": counts["CRITICAL"],
            "HighCount": counts["HIGH"],
            "MediumCount": counts["MEDIUM"],
            "LowCount": counts["LOW"],
        }
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", default="semgrep-results.json")
    parser.add_argument("--trivy", default="trivy-results.json")
    parser.add_argument("--dynamodb-table", default="SecOps-Scan-Metrics")
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--commit-hash", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument(
        "--skip-dynamodb",
        action="store_true",
        help="Skip pushing scan metrics to DynamoDB (for local runs without AWS access)",
    )
    args = parser.parse_args()

    counts = {severity: 0 for severity in SEVERITIES}
    count_semgrep(args.semgrep, counts)
    count_trivy(args.trivy, counts)

    print("Security scan summary:")
    for severity in SEVERITIES:
        print(f"  {severity:<8} {counts[severity]}")

    if args.skip_dynamodb:
        print("\n[security_gate] Skipping DynamoDB metrics push (--skip-dynamodb).")
    elif not args.repository or not args.commit_hash:
        print(
            "\n[security_gate] WARNING: --repository/--commit-hash not set "
            "(GITHUB_REPOSITORY/GITHUB_SHA missing) — skipping DynamoDB metrics push.",
            file=sys.stderr,
        )
    else:
        try:
            put_scan_metrics(args.dynamodb_table, args.region, args.repository, args.commit_hash, counts)
            print(f"\n[security_gate] Pushed scan metrics to DynamoDB table '{args.dynamodb_table}'.")
        except Exception as e:
            print(f"\n[security_gate] WARNING: failed to push scan metrics to DynamoDB: {e}", file=sys.stderr)

    if counts["CRITICAL"] > 0:
        print(f"\n[security_gate] FAIL: {counts['CRITICAL']} Critical finding(s) found.")
        sys.exit(1)

    print("\n[security_gate] PASS: no Critical findings.")
    sys.exit(0)


if __name__ == "__main__":
    main()
