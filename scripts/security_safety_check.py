#!/usr/bin/env python3
"""Check Safety security scan results for vulnerabilities."""

import json
from pathlib import Path
import sys


def main() -> None:
    """Check safety results for any vulnerabilities."""
    report_path = Path("safety-report.json")
    if not report_path.exists():
        print("No safety-report.json found, skipping.")
        return

    with report_path.open() as f:
        data = json.load(f)

    vulnerabilities = data.get("vulnerabilities", [])

    if vulnerabilities:
        print(f"❌ Found {len(vulnerabilities)} Safety vulnerabilities:")
        for vuln in vulnerabilities:
            print(f"  - {vuln.get('package_name', 'Unknown')}: {vuln.get('vulnerability', 'Unknown issue')}")
        sys.exit(1)
    else:
        print("✅ No Safety vulnerabilities found.")


if __name__ == "__main__":
    main()
