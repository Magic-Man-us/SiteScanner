"""Tests for XSS scanner."""

import pytest

from sitescanner.core.result import Severity
from sitescanner.http import MockClient, SimpleResponse
from sitescanner.scanners.xss import XSSPayload, XSSScanner


@pytest.mark.asyncio
async def test_xss_payload_validation():
    """Test Pydantic validation of XSS payloads."""
    payload = XSSPayload(
        payload="<script>alert('XSS')</script>",
        description="Basic script injection",
        detection_patterns=["<script>alert"],
        payload_type="reflected",
    )

    assert payload.payload_type == "reflected"
    assert len(payload.detection_patterns) >= 1


@pytest.mark.asyncio
async def test_xss_payload_type_validation():
    """Test that invalid payload types are rejected."""
    with pytest.raises(ValueError, match="payload_type must be one of"):
        XSSPayload(
            payload="<script>test</script>",
            description="Test",
            payload_type="invalid_type",  # Should fail validation
        )


@pytest.mark.asyncio
async def test_xss_scanner_detects_vulnerability(mock_session, xss_reflected_response):
    """Test XSS detection with mock responses."""
    # Use MockClient to provide the reflected response body. The scanner will
    # inject payloads into the query string; MockClient supports prefix matching.
    client = MockClient(
        {
            "https://example.com/search?q=": SimpleResponse(
                status=200, headers={}, body=xss_reflected_response
            )
        }
    )

    scanner = XSSScanner(client=client)
    vulnerabilities = await scanner.scan_pages(["https://example.com/search?q=test"], mock_session)

    assert len(vulnerabilities) > 0
    assert any("XSS" in v.vuln_type for v in vulnerabilities)
    assert any(v.severity in [Severity.HIGH, Severity.MEDIUM] for v in vulnerabilities)


@pytest.mark.asyncio
async def test_xss_scanner_safe_page(mock_session):
    """Test XSS scanner on safe page with proper encoding."""
    safe_html = "<html><body>Safe content &lt;script&gt;</body></html>"
    client = MockClient(
        {"https://example.com/search?q=": SimpleResponse(status=200, headers={}, body=safe_html)}
    )
    scanner = XSSScanner(client=client)

    vulnerabilities = await scanner.scan_pages(["https://example.com/search?q=test"], mock_session)

    assert len(vulnerabilities) == 0
