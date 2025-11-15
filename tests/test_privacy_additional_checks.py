"""Additional tests for Privacy and Compliance scanner checks."""

import pytest

from sitescanner.http import MockClient, SimpleResponse
from sitescanner.scanners.privacy_and_compliance import PrivacyAndComplianceScanner


@pytest.mark.asyncio
async def test_missing_hsts_and_frame_protection(mock_session):
    # Page returns CSP without frame-ancestors and no HSTS header
    csp = "default-src 'self'; script-src 'self' 'unsafe-inline'"
    headers = {"content-security-policy": csp}
    client = MockClient(
        {"https://example.org/": SimpleResponse(status=200, headers=headers, body="<html></html>")}
    )

    scanner = PrivacyAndComplianceScanner(client=client)
    vulns = await scanner.scan_pages(["https://example.org/"], mock_session)

    # Expect CSP Weakness (unsafe-inline), CSP Missing frame-ancestors, CSP No Reporting, and Missing HSTS
    types = [v.vuln_type for v in vulns]
    assert "CSP Weakness" in types
    assert "CSP Missing frame-ancestors" in types
    assert "CSP No Reporting" in types
    assert "Missing HSTS" in types


@pytest.mark.asyncio
async def test_gdpr_pci_heuristics_detects_missing_privacy_and_card_input(mock_session):
    # Page with a form collecting card info and no privacy link
    html = """
    <html><body>
      <form action="/pay">
        <input name="cardnumber" />
        <input name="expiry" />
      </form>
    </body></html>
    """

    client = MockClient(
        {"https://shop.example/": SimpleResponse(status=200, headers={}, body=html)}
    )
    scanner = PrivacyAndComplianceScanner(client=client)
    vulns = await scanner.scan_pages(["https://shop.example/"], mock_session)

    types = [v.vuln_type for v in vulns]
    assert "Potential PCI Data Collection" in types
    assert "Missing Privacy Policy Link" in types
