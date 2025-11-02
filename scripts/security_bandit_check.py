#!/usr/bin/env python3
"""Check Bandit security scan results against threshold."""

import json
import os
from pathlib import Path
import sys


def main() -> None:
    """Check bandit results against SECURITY_FAIL_LEVEL threshold."""
    fail_level = os.getenv("SECURITY_FAIL_LEVEL", "MEDIUM").upper()
    severity_order = ["LOW", "MEDIUM", "HIGH"]

    if fail_level not in severity_order:
        print(f"Invalid SECURITY_FAIL_LEVEL: {fail_level}")
        sys.exit(1)

    threshold_index = severity_order.index(fail_level)

    report_path = Path("bandit-report.json")
    if not report_path.exists():
        print("No bandit-report.json found, skipping.")
        return

    with report_path.open() as f:
        data = json.load(f)

    results = data.get("results", [])
    issues_above_threshold = [
        r for r in results
        if severity_order.index(r["issue_severity"]) >= threshold_index
    ]

    if issues_above_threshold:
        print(f"❌ Found {len(issues_above_threshold)} Bandit issues at or above {fail_level} severity:")
        for issue in issues_above_threshold:
            print(f"  - {issue['issue_text']} ({issue['issue_severity']}) in {issue['filename']}:{issue['line_number']}")
        sys.exit(1)
    else:
        print(f"✅ No Bandit issues at or above {fail_level} severity.")


if __name__ == "__main__":
    main()
