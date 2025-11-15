"""Nmap-based scanner module.

This scanner is opt-in and uses a runner to execute nmap. Tests mock the runner
and use saved nmap XML fixtures.
"""

from __future__ import annotations

from sitescanner.core.result import Severity, Vulnerability
from sitescanner.runners.nmap_runner import NmapRunner, SubprocessNmapRunner

from .nmap_models import NmapRunModel


class NmapScanner:
    """Scanner that runs nmap and parses results into vulnerabilities.

    Note: This scanner is intended to be explicitely enabled by users.
    """

    DEFAULT_FLAGS: tuple[str, ...] = ("-sV", "-Pn", "--top-ports", "100", "-T4", "-oX", "-")

    def __init__(self, runner: NmapRunner | None = None, flags: list[str] | None = None) -> None:
        self.runner = runner
        # copy into a mutable list for callers who may want to modify
        self.flags = list(flags or list(self.DEFAULT_FLAGS))

    def scan_target(self, target: str) -> list[Vulnerability]:
        runner = self.runner
        if runner is None:
            runner = SubprocessNmapRunner()

        retcode, stdout, stderr = runner.run(target, self.flags)
        if retcode != 0:
            # return empty plus maybe include stderr as an info vuln
            return [
                Vulnerability(
                    vuln_type="Nmap Scan Error",
                    severity=Severity.INFO,
                    url=target,
                    parameter=None,
                    payload=None,
                    evidence=stderr or "nmap returned non-zero exit",
                    description="Nmap invocation failed or returned errors.",
                    remediation="Verify nmap availability and permissions.",
                    cwe_id=None,
                    cvss_score=0.0,
                )
            ]

        # Parse XML via Pydantic models
        try:
            nmap_run = NmapRunModel.from_xml(stdout)
        except Exception:
            return [
                Vulnerability(
                    vuln_type="Nmap Parse Error",
                    severity=Severity.INFO,
                    url=target,
                    parameter=None,
                    payload=None,
                    evidence="Failed to parse nmap XML output",
                    description="nmap output could not be parsed.",
                    remediation="Ensure nmap version and output format are supported.",
                    cwe_id=None,
                    cvss_score=0.0,
                )
            ]

        vulns: list[Vulnerability] = []
        for host in nmap_run.hosts:
            addr_str = host.address or target
            for port in host.ports:
                if port.state != "open":
                    continue

                service_name = port.service.name if port.service is not None else "unknown"
                product = port.service.product if port.service is not None else None
                version = port.service.version if port.service is not None else None

                evidence = f"Open port {port.portid}/{port.protocol} service={service_name}"
                if product:
                    evidence += f" product={product}"
                if version:
                    evidence += f" version={version}"

                vulns.append(
                    Vulnerability(
                        vuln_type="Open Port / Service",
                        severity=Severity.INFO,
                        url=addr_str,
                        parameter=str(port.portid),
                        payload=None,
                        evidence=evidence,
                        description="Nmap discovered an open port and service.",
                        remediation="Review exposed services and apply appropriate hardening.",
                        cwe_id=None,
                        cvss_score=0.0,
                    )
                )

        return vulns
