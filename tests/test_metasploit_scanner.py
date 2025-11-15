from sitescanner.runners.metasploit_runner import MetasploitExploitInfo, MockMetasploitRunner
from sitescanner.scanners.metasploit_scanner import MetasploitScanner


def test_metasploit_scanner_reports_modules() -> None:
    exploits = [
        MetasploitExploitInfo(
            name="exploit/linux/foo", description="Test exploit", references=["CVE-2020-0001"]
        ),
    ]

    runner = MockMetasploitRunner(exploits=exploits)
    scanner = MetasploitScanner(runner=runner)

    vulns = scanner.scan_target("198.51.100.5")
    assert len(vulns) == 1
    assert vulns[0].evidence is not None
    assert "exploit/linux/foo" in vulns[0].evidence
