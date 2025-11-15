#!/usr/bin/env python3
"""Small CLI helper to run Nmap scanner and fuzzy matching to produce triage suggestions.

Usage examples:
  # dry-run using the bundled fixture
  python scripts/nmap_triage.py --target 192.0.2.1

  # run real nmap (requires `nmap` on PATH)
  python scripts/nmap_triage.py --target example.com --use-nmap

Options:
  --rules PATH   : JSON rules file (defaults to bundled match_rules.json)
  --threshold N  : similarity threshold (0-100)
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from sitescanner.scanners.nmap_models import NmapRunModel
from sitescanner.runners.nmap_runner import MockNmapRunner, SubprocessNmapRunner
from sitescanner.scanners.nmap_scanner import NmapScanner
from sitescanner.scanners.nmap_metasploit_fuzzy import match_nmap_to_msf_fuzzy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="Target host or IP")
    parser.add_argument("--use-nmap", action="store_true", help="Run real nmap (requires nmap binary)")
    parser.add_argument("--rules", type=Path, default=None, help="Path to JSON match rules")
    parser.add_argument("--threshold", type=float, default=65.0, help="Similarity threshold (0-100)")
    parser.add_argument("--use-msfrpc", action="store_true", help="Attempt to use pymetasploit3 + msfrpcd (guarded by MSF_RPC_ENABLED env var)")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Output format")
    args = parser.parse_args(argv)

    if args.use_nmap:
        runner = SubprocessNmapRunner()
        scanner = NmapScanner(runner=runner)
        results = scanner.scan_target(args.target)
        # convert Vulnerability list back into NmapRunModel is non-trivial; instead run nmap directly to get XML
        # For simplicity, use SubprocessNmapRunner to invoke nmap and parse XML via NmapScanner's internals
        print("Running real nmap is experimental; prefer --use-nmap only in controlled environments")
        # The scanning flow here will use the runner directly to get XML and parse models
        retcode, stdout, stderr = runner.run(args.target, scanner.flags)
        if retcode != 0:
            print("nmap failed:", stderr)
            return 2
        nmap_run = NmapRunModel.from_xml(stdout)
    else:
        # dry-run using the fixture
        fixture = Path("tests/fixtures/nmap/sample1.xml")
        if not fixture.exists():
            print("Sample fixture not found; run from project root")
            return 1
        xml = fixture.read_text()
        nmap_run = NmapRunModel.from_xml(xml)

    # Optionally use msfrpc (guarded) or fallback to a mock runner
    msf_runner = None
    if args.use_msfrpc:
        import os

        if os.environ.get("MSF_RPC_ENABLED", "false").lower() != "true":
            print("MSF RPC usage is disabled by default. Set MSF_RPC_ENABLED=true to enable.")
            return 2

        try:
            from sitescanner.scanners.pymetasploit_runner import PymetasploitRunner

            msf_host = os.environ.get("MSF_RPC_HOST", "127.0.0.1")
            msf_port = int(os.environ.get("MSF_RPC_PORT", "55553"))
            msf_user = os.environ.get("MSF_RPC_USER")
            msf_pass = os.environ.get("MSF_RPC_PASSWORD")
            msf_ssl = os.environ.get("MSF_RPC_SSL", "false").lower() == "true"

            msf_runner = PymetasploitRunner(host=msf_host, port=msf_port, user=msf_user, password=msf_pass, ssl=msf_ssl)
        except Exception as exc:
            print("Failed to initialize msfrpc runner:", exc)
            return 2

    if msf_runner is None:
        from sitescanner.runners.metasploit_runner import MockMetasploitRunner, MetasploitExploitInfo

        mock_exploits = [MetasploitExploitInfo(name="exploit/linux/nginx_fake", description="nginx RCE")]
        msf_runner = MockMetasploitRunner(exploits=mock_exploits)

    print("Matching nmap results to exploit modules...")
    matches = list(match_nmap_to_msf_fuzzy(nmap_run, msf_runner, threshold=args.threshold, rules_path=args.rules))

    if args.format == "json":
        out = []
        for addr, portid, exploit, score, severity in matches:
            out.append({
                "addr": addr,
                "port": portid,
                "exploit": {"name": exploit.name, "description": exploit.description},
                "score": score,
                "suggested_severity": severity.value,
            })
        print(__import__("json").dumps(out, indent=2))
    else:
        for addr, portid, exploit, score, severity in matches:
            print(f"{addr}:{portid} -> {exploit.name} (score={score:.1f}) suggested={severity.value}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
