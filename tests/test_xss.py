"""Tests for XSS scanner."""

from unittest.mock import AsyncMock

import pytest

from sitescanner.core.result import Severity
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
    with pytest.raises(ValueError):
        XSSPayload(
            payload="<script>test</script>",
            description="Test",
            payload_type="invalid_type",  # Should fail validation
        )


@pytest.mark.asyncio
async def test_xss_scanner_detects_vulnerability(mock_session, xss_reflected_response):
    """Test XSS detection with mock responses."""
    scanner = XSSScanner()

    # Mock response context manager properly
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.text = AsyncMock(return_value=xss_reflected_response)

    mock_context = AsyncMock()
    mock_context.__aenter__.return_value = mock_response
    mock_context.__aexit__.return_value = None
    mock_session.get.return_value = mock_context

    # Scan pages
    vulnerabilities = await scanner.scan_pages(["https://example.com/search?q=test"], mock_session)

    # Should detect XSS
    assert len(vulnerabilities) > 0
    assert any("XSS" in v.vuln_type for v in vulnerabilities)
    assert any(v.severity in [Severity.HIGH, Severity.MEDIUM] for v in vulnerabilities)


@pytest.mark.asyncio
async def test_xss_scanner_safe_page(mock_session):
    """Test XSS scanner on safe page with proper encoding."""
    scanner = XSSScanner()

    safe_html = "<html><body>Safe content &lt;script&gt;</body></html>"
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.text = AsyncMock(return_value=safe_html)

    mock_context = AsyncMock()
    mock_context.__aenter__.return_value = mock_response
    mock_context.__aexit__.return_value = None
    mock_session.get.return_value = mock_context

    vulnerabilities = await scanner.scan_pages(["https://example.com/search?q=test"], mock_session)

    # Should not detect XSS (content is properly encoded)
    assert len(vulnerabilities) == 0
