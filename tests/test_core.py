"""Tests for core scanner and result models."""

from datetime import datetime

import pytest
from pydantic import ValidationError

from sitescanner.core.result import ScanResult, Severity, Vulnerability


def test_vulnerability_model_validation():
    """Test Pydantic validation of Vulnerability model."""
    vuln = Vulnerability(
        vuln_type="SQL Injection",
        severity=Severity.CRITICAL,
        url="https://example.com/page?id=1",
        parameter="id",
        payload="' OR '1'='1",
        evidence="SQL error in response",
        description="SQL injection vulnerability detected",
        remediation="Use parameterized queries",
        cwe_id="CWE-89",
        cvss_score=9.8,
    )

    assert vuln.severity == Severity.CRITICAL
    assert vuln.cvss_score == 9.8
    assert "example.com" in str(vuln.url)


def test_vulnerability_cvss_score_validation():
    """Test that CVSS scores are validated to be between 0 and 10."""
    # Valid score
    vuln = Vulnerability(
        vuln_type="Test",
        severity=Severity.LOW,
        url="https://example.com",
        description="Test vuln",
        remediation="Fix it",
        cvss_score=5.5,
    )
    assert vuln.cvss_score == 5.5

    # Invalid score (too high)
    with pytest.raises(ValidationError):
        Vulnerability(
            vuln_type="Test",
            severity=Severity.LOW,
            url="https://example.com",
            description="Test vuln",
            remediation="Fix it",
            cvss_score=11.0,  # Should fail validation
        )


def test_scan_result_model():
    """Test ScanResult model with Pydantic."""
    result = ScanResult(
        target="https://example.com",
        scan_id="test-123",
        start_time=datetime.now(),
    )

    assert result.vulnerabilities == []
    assert result.pages_scanned == 0
    assert str(result.target) == "https://example.com/"


def test_scan_result_add_vulnerability():
    """Test adding vulnerabilities to scan results."""
    result = ScanResult(
        target="https://example.com",
        scan_id="test-123",
    )

    vuln = Vulnerability(
        vuln_type="XSS",
        severity=Severity.HIGH,
        url="https://example.com",
        description="XSS vulnerability",
        remediation="Encode output",
    )

    result.add_vulnerability(vuln)
    assert len(result.vulnerabilities) == 1
    assert result.get_by_severity(Severity.HIGH)[0] == vuln


def test_scan_result_summary():
    """Test vulnerability summary generation."""
    result = ScanResult(
        target="https://example.com",
        scan_id="test-123",
    )

    # Add multiple vulnerabilities
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.HIGH, Severity.MEDIUM]:
        vuln = Vulnerability(
            vuln_type="Test",
            severity=severity,
            url="https://example.com",
            description="Test vuln",
            remediation="Fix it",
        )
        result.add_vulnerability(vuln)

    summary = result.summary()
    assert summary[Severity.CRITICAL.value] == 1
    assert summary[Severity.HIGH.value] == 2
    assert summary[Severity.MEDIUM.value] == 1
    assert summary[Severity.LOW.value] == 0
