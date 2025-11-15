"""Simple scanner that queries a Metasploit-like runner for matching exploits.

This scanner is intentionally non-intrusive: it only fetches exploit metadata
and produces informational Vulnerability entries suggesting that a manual
investigation may be warranted. It does NOT execute any exploit.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sitescanner.core.result import Severity, Vulnerability

if TYPE_CHECKING:
    from .metasploit_runner import MetasploitRunner


class MetasploitScanner:
    """Scanner that asks a runner for potentially applicable exploits.

    The scanner maps exploit metadata into informational Vulnerability
    objects for downstream reporting. This is a safe-first integration.
    """

    def __init__(self, runner: MetasploitRunner) -> None:
        self.runner = runner

    def scan_target(self, target: str) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        for ei in self.runner.list_exploits(target):
            evidence = f"Module: {ei.name}; {ei.description}"
            if ei.references:
                evidence += " refs=" + ",".join(ei.references)

            vulns.append(
                Vulnerability(
                    vuln_type="Potential Exploit Module",
                    severity=Severity.INFO,
                    url=target,
                    parameter=None,
                    payload=None,
                    evidence=evidence,
                    description=f"Metasploit module {ei.name} may be relevant.",
                    remediation="Investigate the module and validate applicability in a controlled environment.",
                    cwe_id=None,
                    cvss_score=0.0,
                )
            )

        return vulns
