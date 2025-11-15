"""Tests for Privacy and Compliance scanner."""

# Using mock_session fixture instead of inline AsyncMock

# Third-party
import pytest

from sitescanner.core.result import Severity
from sitescanner.http import MockClient, SimpleResponse

# Local
from sitescanner.scanners.privacy_and_compliance import PrivacyAndComplianceScanner


@pytest.mark.asyncio
async def test_robots_detects_gptbot_block(mock_session):
    scanner = PrivacyAndComplianceScanner()

    # Mock robots.txt response
    robots_text = """
User-agent: GPTBot
Disallow: /
"""

    client = MockClient(
        {
            "https://example.com/robots.txt": SimpleResponse(
                status=200, headers={}, body=robots_text
            ),
            "https://example.com/": SimpleResponse(status=200, headers={}, body="<html></html>"),
        }
    )

    scanner = PrivacyAndComplianceScanner(client=client)

    vulns = await scanner.scan_pages(["https://example.com/"], mock_session)

    assert any(v.vuln_type == "Robots.txt: GPTBot Block" for v in vulns)
    assert any(v.severity == Severity.INFO for v in vulns)


@pytest.mark.asyncio
async def test_external_content_detected(mock_session):
    scanner = PrivacyAndComplianceScanner()

    page_html = """
    <html><head></head><body>
    <script src="https://thirdparty.com/lib.js"></script>
    <img src="https://cdn.example.org/image.png" />
    </body></html>
    """

    client = MockClient(
        {"https://example.com/": SimpleResponse(status=200, headers={}, body=page_html)}
    )
    scanner = PrivacyAndComplianceScanner(client=client)

    vulns = await scanner.scan_pages(["https://example.com/"], mock_session)

    assert any(v.vuln_type == "External Content" for v in vulns)
    assert any(v.severity == Severity.INFO for v in vulns)
