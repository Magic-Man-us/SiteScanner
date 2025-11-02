"""Security configuration and misconfiguration scanner with Pydantic validation."""

import asyncio
import logging

import aiohttp
from pydantic import BaseModel, Field

from sitescanner.core.result import Severity, Vulnerability

logger = logging.getLogger(__name__)


class SecurityHeader(BaseModel):
    """Pydantic model for security header configuration."""

    name: str = Field(..., min_length=1, description="Header name")
    expected: bool = Field(default=True, description="Should header be present")
    recommended_value: str | None = Field(None, description="Recommended header value")
    severity_if_missing: Severity = Field(default=Severity.MEDIUM)
    description: str = Field(..., description="What this header protects against")


class ConfigTestCase(BaseModel):
    """Pydantic model for configuration test case."""

    url: str  # Allow string URLs for internal use
    test_type: str = Field(..., description="Type of config check")
    headers_checked: dict[str, str] = Field(default_factory=dict)
    missing_headers: list[str] = Field(default_factory=list)
    response_code: int | None = None
    server_info: str | None = None


class TLSConfiguration(BaseModel):
    """Pydantic model for TLS/SSL configuration."""

    url: str  # Allow string URLs for internal use
    uses_https: bool = False
    tls_version: str | None = None
    has_hsts: bool = False
    hsts_max_age: int | None = Field(default=None, ge=0)
    certificate_valid: bool | None = None


class ConfigScanner:
    """Scanner for security misconfigurations using Pydantic validation."""

    # Security headers to check with Pydantic models
    SECURITY_HEADERS = [
        SecurityHeader(
            name="X-Frame-Options",
            expected=True,
            recommended_value="DENY",
            severity_if_missing=Severity.MEDIUM,
            description="Prevents clickjacking attacks by controlling iframe embedding",
        ),
        SecurityHeader(
            name="X-Content-Type-Options",
            expected=True,
            recommended_value="nosniff",
            severity_if_missing=Severity.LOW,
            description="Prevents MIME-sniffing attacks",
        ),
        SecurityHeader(
            name="Strict-Transport-Security",
            expected=True,
            recommended_value="max-age=31536000; includeSubDomains",
            severity_if_missing=Severity.MEDIUM,
            description="Enforces HTTPS and prevents SSL-stripping attacks",
        ),
        SecurityHeader(
            name="Content-Security-Policy",
            expected=True,
            recommended_value="default-src 'self'",
            severity_if_missing=Severity.MEDIUM,
            description="Mitigates XSS and data injection attacks",
        ),
        SecurityHeader(
            name="X-XSS-Protection",
            expected=True,
            recommended_value="1; mode=block",
            severity_if_missing=Severity.LOW,
            description="Enables browser XSS filtering (legacy, use CSP instead)",
        ),
        SecurityHeader(
            name="Referrer-Policy",
            expected=True,
            recommended_value="strict-origin-when-cross-origin",
            severity_if_missing=Severity.LOW,
            description="Controls referrer information leakage",
        ),
        SecurityHeader(
            name="Permissions-Policy",
            expected=True,
            recommended_value="geolocation=(), camera=(), microphone=()",
            severity_if_missing=Severity.INFO,
            description="Controls browser features and APIs",
        ),
    ]

    # Headers that should NOT be present (information disclosure)
    DANGEROUS_HEADERS = [
        SecurityHeader(
            name="Server",
            expected=False,
            recommended_value=None,
            severity_if_missing=Severity.LOW,
            description="Server header reveals technology stack",
        ),
        SecurityHeader(
            name="X-Powered-By",
            expected=False,
            recommended_value=None,
            severity_if_missing=Severity.LOW,
            description="X-Powered-By reveals framework/language versions",
        ),
        SecurityHeader(
            name="X-AspNet-Version",
            expected=False,
            recommended_value=None,
            severity_if_missing=Severity.LOW,
            description="Reveals ASP.NET version",
        ),
    ]

    async def scan_pages(
        self, pages: list[str], session: aiohttp.ClientSession
    ) -> list[Vulnerability]:
        """Scan multiple pages for configuration issues.

        Args:
            pages: List of URLs to scan
            session: aiohttp session for making requests

        Returns:
            List of detected configuration vulnerabilities
        """
        vulnerabilities: list[Vulnerability] = []

        tasks = [self._scan_page(page, session) for page in pages]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                vulnerabilities.extend(result)
            elif isinstance(result, Exception):
                logger.error(f"Error scanning page for config issues: {result}")

        return vulnerabilities

    async def _scan_page(self, url: str, session: aiohttp.ClientSession) -> list[Vulnerability]:
        """Scan a single page for security configuration issues.

        Args:
            url: Target URL to scan
            session: aiohttp session for making requests

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities: list[Vulnerability] = []

        try:
            async with session.get(url) as response:
                headers = {k.lower(): v for k, v in response.headers.items()}

                # Create test case with Pydantic validation
                test_case = ConfigTestCase(
                    url=url,
                    test_type="security_headers",
                    headers_checked=headers,
                    response_code=response.status,
                    server_info=headers.get("server"),
                )

                # Check for missing security headers
                for sec_header in self.SECURITY_HEADERS:
                    if sec_header.name.lower() not in headers:
                        test_case.missing_headers.append(sec_header.name)
                        vulnerabilities.append(
                            self._create_missing_header_vulnerability(sec_header, test_case)
                        )

                # Check for dangerous headers that should not be present
                for danger_header in self.DANGEROUS_HEADERS:
                    if danger_header.name.lower() in headers:
                        vulnerabilities.append(
                            self._create_info_disclosure_vulnerability(
                                danger_header, headers[danger_header.name.lower()], test_case
                            )
                        )

                # Check TLS configuration
                tls_vulns = await self._check_tls_config(url, headers)
                vulnerabilities.extend(tls_vulns)

        except Exception as e:
            logger.debug(f"Error checking config on {url}: {e}")

        return vulnerabilities

    def _create_missing_header_vulnerability(
        self, header: SecurityHeader, test_case: ConfigTestCase
    ) -> Vulnerability:
        """Create vulnerability for missing security header.

        Args:
            header: Security header configuration
            test_case: Test case with results

        Returns:
            Vulnerability instance
        """
        return Vulnerability(
            vuln_type="Missing Security Header",
            severity=header.severity_if_missing,
            url=test_case.url,
            parameter=None,
            payload=None,
            evidence=f"Security header '{header.name}' is not present in response",
            description=f"The security header '{header.name}' is missing. {header.description}.",
            remediation=f"Add '{header.name}: {header.recommended_value or '<appropriate-value>'}' header to all responses. Configure your web server or application framework to include this header.",
            cwe_id="CWE-16",
            cvss_score=self._severity_to_cvss(header.severity_if_missing),
        )

    def _create_info_disclosure_vulnerability(
        self, header: SecurityHeader, value: str, test_case: ConfigTestCase
    ) -> Vulnerability:
        """Create vulnerability for information disclosure header.

        Args:
            header: Header configuration
            value: Actual header value found
            test_case: Test case with results

        Returns:
            Vulnerability instance
        """
        return Vulnerability(
            vuln_type="Information Disclosure",
            severity=Severity.LOW,
            url=test_case.url,
            parameter=None,
            payload=None,
            evidence=f"Header '{header.name}' present with value: {value}",
            description=f"The response includes '{header.name}' header which discloses server implementation details. {header.description}. This information can aid attackers in targeting specific vulnerabilities.",
            remediation=f"Remove or obscure the '{header.name}' header. Configure your web server to suppress version information and technology stack details.",
            cwe_id="CWE-200",
            cvss_score=3.1,
        )

    async def _check_tls_config(self, url: str, headers: dict[str, str]) -> list[Vulnerability]:
        """Check TLS/HTTPS configuration using Pydantic validation.

        Args:
            url: Target URL
            headers: Response headers

        Returns:
            List of TLS-related vulnerabilities
        """
        vulnerabilities: list[Vulnerability] = []

        tls_config = TLSConfiguration(
            url=url,
            uses_https=url.startswith("https://"),
        )

        # Check for HSTS header
        hsts_header = headers.get("strict-transport-security")
        if hsts_header:
            tls_config.has_hsts = True
            # Parse max-age if present
            if "max-age=" in hsts_header:
                try:
                    max_age_str = hsts_header.split("max-age=")[1].split(";")[0].strip()
                    tls_config.hsts_max_age = int(max_age_str)
                except (ValueError, IndexError):
                    pass

        # Report if HTTPS is not used
        if not tls_config.uses_https:
            vulnerabilities.append(
                Vulnerability(
                    vuln_type="Insecure Transport",
                    severity=Severity.HIGH,
                    url=tls_config.url,
                    parameter=None,
                    payload=None,
                    evidence="Site accessible over HTTP without HTTPS redirection",
                    description="The application is accessible over unencrypted HTTP. Sensitive data transmitted over HTTP can be intercepted by attackers.",
                    remediation="Enable HTTPS for all pages. Configure HTTP to HTTPS redirection. Obtain valid TLS certificate. Implement HSTS header.",
                    cwe_id="CWE-319",
                    cvss_score=7.4,
                )
            )

        # Check HSTS configuration for HTTPS sites
        if tls_config.uses_https and not tls_config.has_hsts:
            vulnerabilities.append(
                Vulnerability(
                    vuln_type="Missing HSTS Header",
                    severity=Severity.MEDIUM,
                    url=tls_config.url,
                    parameter=None,
                    payload=None,
                    evidence="HTTPS enabled but Strict-Transport-Security header not present",
                    description="The site uses HTTPS but does not enforce it with HSTS. Users may still access the site over HTTP, making them vulnerable to SSL-stripping attacks.",
                    remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header to enforce HTTPS.",
                    cwe_id="CWE-523",
                    cvss_score=5.9,
                )
            )

        return vulnerabilities

    @staticmethod
    def _severity_to_cvss(severity: Severity) -> float:
        """Convert Severity enum to CVSS score.

        Args:
            severity: Severity level

        Returns:
            Approximate CVSS score
        """
        mapping = {
            Severity.CRITICAL: 9.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.5,
            Severity.LOW: 3.5,
            Severity.INFO: 0.0,
        }
        return mapping.get(severity, 5.0)
