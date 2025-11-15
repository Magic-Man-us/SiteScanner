from pathlib import Path

from sitescanner.runners.metasploit_runner import MetasploitExploitInfo, MockMetasploitRunner
from sitescanner.scanners.nmap_metasploit_matcher import match_nmap_to_msf
from sitescanner.scanners.nmap_models import NmapRunModel


def test_matcher_finds_modules_for_nginx() -> None:
    xml = Path("tests/fixtures/nmap/sample1.xml").read_text()
    nmap_run = NmapRunModel.from_xml(xml)

    # mock that returns one exploit when queried
    exploit = MetasploitExploitInfo(
        name="exploit/linux/nginx_fake", description="nginx RCE", references=["CVE-2020-0002"]
    )
    runner = MockMetasploitRunner(exploits=[exploit])

    matches = list(match_nmap_to_msf(nmap_run, runner))
    assert len(matches) == 1
    _host, portid, found = matches[0]
    assert int(portid) == 80
    assert "nginx" in found.description.lower()
