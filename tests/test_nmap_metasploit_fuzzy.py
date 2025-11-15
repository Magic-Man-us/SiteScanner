from pathlib import Path

from sitescanner.core.result import Severity
from sitescanner.runners.metasploit_runner import MetasploitExploitInfo, MockMetasploitRunner
from sitescanner.scanners.nmap_metasploit_fuzzy import match_nmap_to_msf_fuzzy
from sitescanner.scanners.nmap_models import NmapRunModel


def test_fuzzy_matcher_suggests_medium_for_nginx() -> None:
    xml = Path("tests/fixtures/nmap/sample1.xml").read_text()
    nmap_run = NmapRunModel.from_xml(xml)

    exploit = MetasploitExploitInfo(name="exploit/linux/nginx_fake", description="nginx RCE")
    runner = MockMetasploitRunner(exploits=[exploit])

    matches = list(match_nmap_to_msf_fuzzy(nmap_run, runner, threshold=10.0))
    assert len(matches) == 1
    _addr, portid, exploit, _score, suggested = matches[0]
    assert int(portid) == 80
    assert suggested == Severity.MEDIUM
