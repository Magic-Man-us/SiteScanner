"""Tests for SQL injection scanner."""

# AsyncMock not needed here; tests use mock_session fixture

import pytest

from sitescanner.core.result import Severity
from sitescanner.http import MockClient, SimpleResponse
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
    with pytest.raises(ValueError, match="Payload cannot be empty or whitespace"):
        SQLInjectionPayload(
            payload="   ",  # Only whitespace
            description="Invalid payload",
        )


@pytest.mark.asyncio
async def test_sql_scanner_detects_vulnerability(mock_session, vulnerable_sql_response):
    """Test SQL injection detection with mock responses."""
    # Create a MockClient mapping for the test URL (the scanner builds test URLs by changing the id param)
    # We'll map any test URL prefix to a response containing the vulnerable SQL indicator string
    # For simplicity, map the base URL that scanner will also fetch
    scanner = SQLInjectionScanner()

    # The scanner will generate multiple test URLs with injected payloads. In our MockClient we provide
    # a default response body that contains the SQL error indicator used in fixtures (vulnerable_sql_response).
    # The MockClient returns a default body when URL not in mapping, so we map the base URL to include
    # the vulnerable content.
    client = MockClient(
        {
            "https://example.com/page?id=1": SimpleResponse(
                status=200, headers={}, body=vulnerable_sql_response
            ),
        }
    )

    scanner = SQLInjectionScanner(client=client)

    # Scan pages; pass the standardized mock_session fixture (client is used instead)
    vulnerabilities = await scanner.scan_pages(["https://example.com/page?id=1"], mock_session)

    # Should detect SQL injection
    assert len(vulnerabilities) > 0
    assert any(v.vuln_type == "SQL Injection" for v in vulnerabilities)
    assert any(v.severity == Severity.CRITICAL for v in vulnerabilities)


@pytest.mark.asyncio
async def test_sql_scanner_no_parameters(mock_session):
    """Test SQL scanner with URL without parameters."""
    # No parameters -> no tests executed. Use MockClient for deterministic behaviour.
    client = MockClient(
        {
            "https://example.com/page": SimpleResponse(
                status=200, headers={}, body="<html>Safe page</html>"
            )
        }
    )
    scanner = SQLInjectionScanner(client=client)

    vulnerabilities = await scanner.scan_pages(["https://example.com/page"], mock_session)

    # Should return empty list (no parameters to test)
    assert len(vulnerabilities) == 0
