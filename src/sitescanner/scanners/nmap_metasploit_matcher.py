"""Match Nmap scan results to Metasploit module metadata.

This module provides a simple matching function that, given parsed Nmap
results and a MetasploitRunner, returns potential module matches for each
open port/service. Matching is conservative: it performs substring checks
against module names and descriptions and can be extended later with fuzzy
matching or curated rules.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from sitescanner.runners.metasploit_runner import MetasploitExploitInfo, MetasploitRunner

    from .nmap_models import NmapRunModel


def match_nmap_to_msf(
    nmap_run: NmapRunModel, runner: MetasploitRunner
) -> Iterable[tuple[str, int, MetasploitExploitInfo]]:
    """Yield tuples of (host_address, portid, MetasploitExploitInfo) for matches."""
    for host in nmap_run.hosts:
        addr = host.address
        for port in host.ports:
            if port.state != "open":
                continue

            service_name = port.service.name if port.service is not None else ""
            product = port.service.product if port.service is not None else ""
            version = port.service.version if port.service is not None else ""

            # Build a simple fingerprint string to query runner
            fingerprint = f"{service_name} {product} {version} {addr}"

            for exploit in runner.list_exploits(fingerprint):
                # Conservative checks already performed by runner; yield results
                yield (addr, port.portid, exploit)
