"""Data models for scan results and vulnerabilities."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, HttpUrl


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Vulnerability(BaseModel):
    """Represents a detected security vulnerability."""

    vuln_type: str = Field(..., description="Type of vulnerability detected")
    severity: Severity = Field(..., description="Severity level")
    url: HttpUrl | str = Field(..., description="URL where vulnerability was found")
    parameter: str | None = Field(None, description="Vulnerable parameter name")
    payload: str | None = Field(None, description="Test payload that triggered detection")
    evidence: str | None = Field(None, description="Evidence of vulnerability")
    description: str = Field(..., description="Human-readable description")
    remediation: str = Field(..., description="Recommended fix")
    cwe_id: str | None = Field(None, description="Common Weakness Enumeration ID")
    cvss_score: float | None = Field(None, ge=0.0, le=10.0, description="CVSS score")


class ScanResult(BaseModel):
    """Complete scan result for a target."""

    target: HttpUrl = Field(..., description="Scanned target URL")
    scan_id: str = Field(..., description="Unique scan identifier")
    start_time: datetime = Field(default_factory=datetime.now)
    end_time: datetime | None = None
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    pages_scanned: int = 0
    scan_duration: float | None = None
    scanner_version: str = "0.1.0"

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        """Add a vulnerability to the scan results."""
        self.vulnerabilities.append(vuln)

    def get_by_severity(self, severity: Severity) -> list[Vulnerability]:
        """Filter vulnerabilities by severity level."""
        return [v for v in self.vulnerabilities if v.severity == severity]

    def summary(self) -> dict[str, int]:
        """Get vulnerability count summary by severity."""
        return {severity.value: len(self.get_by_severity(severity)) for severity in Severity}
