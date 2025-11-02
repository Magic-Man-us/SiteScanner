"""Cross-Site Scripting (XSS) vulnerability scanner with Pydantic validation."""

import asyncio
import logging
from typing import TYPE_CHECKING
from urllib.parse import ParseResult, parse_qs, urlencode, urlparse, urlunparse

import aiohttp
from bs4 import BeautifulSoup
from pydantic import BaseModel, Field, field_validator

if TYPE_CHECKING:
    pass

from sitescanner.core.result import Severity, Vulnerability

logger = logging.getLogger(__name__)


class XSSPayload(BaseModel):
    """Pydantic model for XSS test payloads."""

    payload: str = Field(..., min_length=1, description="XSS test vector")
    description: str = Field(..., description="Type of XSS this payload tests")
    detection_patterns: list[str] = Field(
        default_factory=list, description="Patterns to detect in response"
    )
    payload_type: str = Field(..., description="reflected, stored, or dom")

    @field_validator("payload_type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        """Validate XSS payload type."""
        allowed = {"reflected", "stored", "dom"}
        if v.lower() not in allowed:
            raise ValueError(f"payload_type must be one of {allowed}")
        return v.lower()


class XSSTestCase(BaseModel):
    """Pydantic model for an XSS test case."""

    url: str  # Allow string URLs for internal use
    parameter: str | None = None
    test_payload: XSSPayload
    response_code: int | None = None
    response_body: str | None = None
    injection_point: str = Field(..., description="URL parameter, form field, or DOM location")


class XSSScanner:
    """Scanner for XSS vulnerabilities using Pydantic validation."""

    # XSS test payloads with Pydantic validation
    PAYLOADS = [
        XSSPayload(
            payload="<script>alert('XSS')</script>",
            description="Basic script injection",
            detection_patterns=["<script>alert('XSS')</script>", "<script>alert"],
            payload_type="reflected",
        ),
        XSSPayload(
            payload="<img src=x onerror=alert('XSS')>",
            description="Image tag event handler",
            detection_patterns=["<img src=x onerror=", "onerror=alert"],
            payload_type="reflected",
        ),
        XSSPayload(
            payload="<svg/onload=alert('XSS')>",
            description="SVG-based XSS",
            detection_patterns=["<svg/onload=", "<svg onload="],
            payload_type="reflected",
        ),
        XSSPayload(
            payload="'><script>alert(String.fromCharCode(88,83,83))</script>",
            description="Attribute escape XSS",
            detection_patterns=["'><script>", "String.fromCharCode"],
            payload_type="reflected",
        ),
        XSSPayload(
            payload='"><script>alert(document.domain)</script>',
            description="Double-quote escape XSS",
            detection_patterns=['"><script>', "alert(document.domain)"],
            payload_type="reflected",
        ),
        XSSPayload(
            payload="javascript:alert('XSS')",
            description="JavaScript protocol handler",
            detection_patterns=["javascript:alert", "javascript:"],
            payload_type="dom",
        ),
        XSSPayload(
            payload="<iframe src='javascript:alert(\"XSS\")'></iframe>",
            description="Iframe JavaScript injection",
            detection_patterns=["<iframe src='javascript:", "<iframe"],
            payload_type="reflected",
        ),
    ]

    async def scan_pages(
        self, pages: list[str], session: aiohttp.ClientSession
    ) -> list[Vulnerability]:
        """Scan multiple pages for XSS vulnerabilities.

        Args:
            pages: List of URLs to scan
            session: aiohttp session for making requests

        Returns:
            List of detected XSS vulnerabilities
        """
        vulnerabilities: list[Vulnerability] = []

        tasks = [self._scan_page(page, session) for page in pages]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                vulnerabilities.extend(result)
            elif isinstance(result, Exception):
                logger.error(f"Error scanning page for XSS: {result}")

        return vulnerabilities

    async def _scan_page(self, url: str, session: aiohttp.ClientSession) -> list[Vulnerability]:
        """Scan a single page for XSS vulnerabilities.

        Args:
            url: Target URL to scan
            session: aiohttp session for making requests

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities: list[Vulnerability] = []

        # Test URL parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if params:
            for param_name in params:
                for payload_model in self.PAYLOADS:
                    try:
                        test_case = XSSTestCase(
                            url=url,
                            parameter=param_name,
                            test_payload=payload_model,
                            injection_point=f"URL parameter: {param_name}",
                        )

                        vuln = await self._test_parameter(test_case, session, parsed, params)
                        if vuln:
                            vulnerabilities.append(vuln)

                    except Exception as e:
                        logger.debug(f"Error testing XSS on {param_name}: {e}")

        # Test form inputs
        form_vulns = await self._scan_forms(url, session)
        vulnerabilities.extend(form_vulns)

        return vulnerabilities

    async def _test_parameter(
        self,
        test_case: XSSTestCase,
        session: aiohttp.ClientSession,
        parsed_url: ParseResult,
        original_params: dict[str, list[str]],
    ) -> Vulnerability | None:
        """Test a URL parameter for XSS vulnerability.

        Args:
            test_case: Pydantic-validated test case
            session: aiohttp session
            parsed_url: Parsed URL tuple
            original_params: Original query parameters

        Returns:
            Vulnerability if detected, None otherwise
        """
        # Create modified parameters with XSS payload
        if not test_case.parameter:
            return None

        test_params = original_params.copy()
        test_params[test_case.parameter] = [test_case.test_payload.payload]

        # Rebuild URL
        new_query = urlencode(test_params, doseq=True)
        test_url = urlunparse(
            (
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment,
            )
        )

        try:
            async with session.get(test_url) as response:
                body = await response.text()
                test_case.response_code = response.status
                test_case.response_body = body[:1000]

                # Check if payload is reflected in response
                for pattern in test_case.test_payload.detection_patterns:
                    if pattern in body:
                        return Vulnerability(
                            vuln_type="Cross-Site Scripting (XSS)",
                            severity=Severity.HIGH,
                            url=test_case.url,
                            parameter=test_case.parameter,
                            payload=test_case.test_payload.payload,
                            evidence=f"XSS payload reflected in response. Pattern '{pattern}' found unescaped.",
                            description=f"XSS vulnerability detected in parameter '{test_case.parameter}'. {test_case.test_payload.description}. User input is reflected in response without proper encoding.",
                            remediation="Implement output encoding/escaping for all user-controlled data. Use Content-Security-Policy headers. Sanitize input and validate against allowlists. Use framework-provided XSS protection.",
                            cwe_id="CWE-79",
                            cvss_score=7.1,
                        )

        except Exception as e:
            logger.debug(f"Request failed for {test_url}: {e}")

        return None

    async def _scan_forms(self, url: str, session: aiohttp.ClientSession) -> list[Vulnerability]:
        """Scan HTML forms on a page for XSS vulnerabilities.

        Args:
            url: Page URL to scan
            session: aiohttp session

        Returns:
            List of XSS vulnerabilities found in forms
        """
        vulnerabilities: list[Vulnerability] = []

        try:
            async with session.get(url) as response:
                html = await response.text()
                soup = BeautifulSoup(html, "html.parser")

                forms = soup.find_all("form")
                for form in forms:
                    inputs = form.find_all(["input", "textarea"])
                    for input_field in inputs:
                        input_name = input_field.get("name")
                        if input_name:
                            # Additional form testing logic would go here
                            # Skipped for brevity in this example
                            pass

        except Exception as e:
            logger.debug(f"Error scanning forms on {url}: {e}")

        return vulnerabilities
