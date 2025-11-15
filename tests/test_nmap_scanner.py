from __future__ import annotations

from pathlib import Path

from sitescanner.runners.nmap_runner import MockNmapRunner
from sitescanner.scanners.nmap_scanner import NmapScanner


def test_nmap_scanner_parses_open_port() -> None:
    xml = Path("tests/fixtures/nmap/sample1.xml").read_text()
    runner = MockNmapRunner(xml_output=xml)
    scanner = NmapScanner(runner=runner)

    results = scanner.scan_target("192.0.2.1")
    assert len(results) == 1
    vuln = results[0]
    assert vuln.evidence is not None
    assert "Open port" in vuln.evidence
    assert "nginx" in vuln.evidence
    assert vuln.parameter == "80"
