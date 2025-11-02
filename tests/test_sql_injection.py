"""Tests for SQL injection scanner."""

from unittest.mock import AsyncMock

import pytest

from sitescanner.core.result import Severity
from sitescanner.scanners.sql_injection import SQLInjectionPayload, SQLInjectionScanner


@pytest.mark.asyncio
async def test_sql_payload_validation():
    """Test Pydantic validation of SQL injection payloads."""
    payload = SQLInjectionPayload(
        payload="' OR '1'='1",
        description="Classic SQL injection",
        error_indicators=["sql syntax", "mysql_fetch"],
    )

    assert payload.payload == "' OR '1'='1"
    assert len(payload.error_indicators) == 2


@pytest.mark.asyncio
async def test_sql_payload_empty_validation():
    """Test that empty payloads are rejected."""
    with pytest.raises(ValueError):
        SQLInjectionPayload(
            payload="   ",  # Only whitespace
            description="Invalid payload",
        )


@pytest.mark.asyncio
async def test_sql_scanner_detects_vulnerability(mock_session, vulnerable_sql_response):
    """Test SQL injection detection with mock responses."""
    scanner = SQLInjectionScanner()

    # Mock response context manager properly
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.text = AsyncMock(return_value=vulnerable_sql_response)

    mock_context = AsyncMock()
    mock_context.__aenter__.return_value = mock_response
    mock_context.__aexit__.return_value = None
    mock_session.get.return_value = mock_context

    # Scan pages
    vulnerabilities = await scanner.scan_pages(
        ["https://example.com/page?id=1"],
        mock_session
    )

    # Should detect SQL injection
    assert len(vulnerabilities) > 0
    assert any(v.vuln_type == "SQL Injection" for v in vulnerabilities)
    assert any(v.severity == Severity.CRITICAL for v in vulnerabilities)


@pytest.mark.asyncio
async def test_sql_scanner_no_parameters(mock_session):
    """Test SQL scanner with URL without parameters."""
    scanner = SQLInjectionScanner()

    mock_response = AsyncMock()
    mock_response.text = AsyncMock(return_value="<html>Safe page</html>")
    mock_session.get = AsyncMock(return_value=mock_response)

    vulnerabilities = await scanner.scan_pages(
        ["https://example.com/page"],
        mock_session
    )

    # Should return empty list (no parameters to test)
    assert len(vulnerabilities) == 0
