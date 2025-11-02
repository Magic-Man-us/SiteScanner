"""Cross-Site Request Forgery (CSRF) vulnerability scanner with Pydantic validation."""

import asyncio
import logging
from typing import Any

import aiohttp
from bs4 import BeautifulSoup
from pydantic import BaseModel, Field

from sitescanner.core.result import Severity, Vulnerability

logger = logging.getLogger(__name__)


class CSRFTestCase(BaseModel):
    """Pydantic model for CSRF test case."""

    url: str  # Allow string URLs for internal use
    form_action: str | None = None
    form_method: str = Field(default="POST", pattern="^(GET|POST|PUT|DELETE|PATCH)$")
    has_csrf_token: bool = False
    token_field_name: str | None = None
    form_fields: dict[str, str] = Field(default_factory=dict)
    missing_protections: list[str] = Field(default_factory=list)


class CSRFProtectionCheck(BaseModel):
    """Pydantic model for CSRF protection mechanisms."""

    has_csrf_token: bool = Field(default=False, description="Form has CSRF token field")
    has_origin_check: bool = Field(default=False, description="Server checks Origin/Referer header")
    has_samesite_cookie: bool = Field(default=False, description="Cookies have SameSite attribute")
    has_custom_header: bool = Field(default=False, description="Requires custom X- header")
    protection_level: str = Field(default="none", description="Overall protection level")

    def calculate_protection_level(self) -> str:
        """Calculate overall CSRF protection level."""
        protections = sum(
            [
                self.has_csrf_token,
                self.has_origin_check,
                self.has_samesite_cookie,
                self.has_custom_header,
            ]
        )

        protection_levels = {
            0: "none",
            1: "weak",
            2: "moderate",
        }
        return protection_levels.get(protections, "strong")


class CSRFScanner:
    """Scanner for CSRF vulnerabilities using Pydantic validation."""

    # Common CSRF token field names
    CSRF_TOKEN_NAMES = [
        "csrf_token",
        "csrftoken",
        "csrf",
        "_csrf",
        "authenticity_token",
        "__requestverificationtoken",
        "token",
        "_token",
        "csrfmiddlewaretoken",
    ]

    async def scan_pages(
        self, pages: list[str], session: aiohttp.ClientSession
    ) -> list[Vulnerability]:
        """Scan multiple pages for CSRF vulnerabilities.

        Args:
            pages: List of URLs to scan
            session: aiohttp session for making requests

        Returns:
            List of detected CSRF vulnerabilities
        """
        vulnerabilities: list[Vulnerability] = []

        tasks = [self._scan_page(page, session) for page in pages]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                vulnerabilities.extend(result)
            elif isinstance(result, Exception):
                logger.error(f"Error scanning page for CSRF: {result}")

        return vulnerabilities

    async def _scan_page(self, url: str, session: aiohttp.ClientSession) -> list[Vulnerability]:
        """Scan a single page for CSRF vulnerabilities.

        Args:
            url: Target URL to scan
            session: aiohttp session for making requests

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities: list[Vulnerability] = []

        try:
            async with session.get(url) as response:
                html = await response.text()
                headers = response.headers
                cookies = response.cookies

                # Parse HTML for forms
                soup = BeautifulSoup(html, "html.parser")
                forms = soup.find_all("form")

                for form in forms:
                    test_case = self._analyze_form(form, url)
                    protection = self._check_csrf_protection(
                        test_case, dict(headers), dict(cookies)
                    )

                    # Generate vulnerability if protections are insufficient
                    if protection.calculate_protection_level() in ["none", "weak"]:
                        vuln = self._create_vulnerability(test_case, protection)
                        if vuln:
                            vulnerabilities.append(vuln)

        except Exception as e:
            logger.debug(f"Error scanning {url} for CSRF: {e}")

        return vulnerabilities

    def _analyze_form(self, form: Any, page_url: str) -> CSRFTestCase:
        """Analyze a form for CSRF protection using Pydantic validation.

        Args:
            form: BeautifulSoup form element
            page_url: URL where form was found

        Returns:
            Validated CSRFTestCase
        """
        form_action_raw = form.get("action", "")
        form_action = (
            form_action_raw
            if isinstance(form_action_raw, str)
            else (form_action_raw[0] if form_action_raw else "")
        )

        form_method_raw = form.get("method", "GET")
        form_method = (
            form_method_raw
            if isinstance(form_method_raw, str)
            else (form_method_raw[0] if form_method_raw else "GET")
        ).upper()

        # Extract all form fields
        fields: dict[str, str] = {}
        csrf_token_field: str | None = None
        has_csrf = False

        inputs = form.find_all(["input", "textarea", "select"])
        for input_field in inputs:
            field_name_raw = input_field.get("name", "")
            field_value_raw = input_field.get("value", "")

            # Extract string values
            field_name = field_name_raw if isinstance(field_name_raw, str) else ""
            field_value = field_value_raw if isinstance(field_value_raw, str) else ""

            if field_name:
                fields[field_name] = field_value

                # Check if this is a CSRF token field
                if field_name.lower() in self.CSRF_TOKEN_NAMES:
                    has_csrf = True
                    csrf_token_field = field_name

        missing_protections: list[str] = []
        if not has_csrf:
            missing_protections.append("CSRF token field")

        return CSRFTestCase(
            url=page_url,
            form_action=form_action if form_action else None,
            form_method=(
                form_method if form_method in ["GET", "POST", "PUT", "DELETE", "PATCH"] else "POST"
            ),
            has_csrf_token=has_csrf,
            token_field_name=csrf_token_field,
            form_fields=fields,
            missing_protections=missing_protections,
        )

    def _check_csrf_protection(
        self,
        test_case: CSRFTestCase,
        headers: dict[str, str],
        cookies: dict[str, Any],
    ) -> CSRFProtectionCheck:
        """Check for various CSRF protection mechanisms.

        Args:
            test_case: Form test case
            headers: Response headers
            cookies: Response cookies

        Returns:
            Validated CSRFProtectionCheck
        """
        protection = CSRFProtectionCheck(has_csrf_token=test_case.has_csrf_token)

        # Check for SameSite cookie attribute
        for cookie in cookies.values():
            if hasattr(cookie, "get") and callable(cookie.get) and cookie.get("samesite"):
                protection.has_samesite_cookie = True
                break

        # Check for custom header requirements (indicated by CORS headers)
        if "Access-Control-Allow-Headers" in headers:
            allowed_headers = headers["Access-Control-Allow-Headers"].lower()
            if "x-" in allowed_headers or "csrf" in allowed_headers:
                protection.has_custom_header = True

        protection.protection_level = protection.calculate_protection_level()

        return protection

    def _create_vulnerability(
        self,
        test_case: CSRFTestCase,
        protection: CSRFProtectionCheck,
    ) -> Vulnerability | None:
        """Create a CSRF vulnerability report.

        Args:
            test_case: Analyzed form test case
            protection: Protection check results

        Returns:
            Vulnerability if CSRF issue detected, None otherwise
        """
        # Only report state-changing methods
        if test_case.form_method in ["GET", "HEAD", "OPTIONS"]:
            return None

        severity = Severity.HIGH if protection.protection_level == "none" else Severity.MEDIUM

        missing = (
            ", ".join(test_case.missing_protections)
            if test_case.missing_protections
            else "Multiple protections"
        )

        return Vulnerability(
            vuln_type="Cross-Site Request Forgery (CSRF)",
            severity=severity,
            url=test_case.url,
            parameter=None,
            payload=None,
            evidence=f"Form with method '{test_case.form_method}' lacks adequate CSRF protection. Protection level: {protection.protection_level}. Missing: {missing}",
            description=f"CSRF vulnerability detected on form. The form submits to '{test_case.form_action or 'same page'}' using {test_case.form_method} without sufficient anti-CSRF tokens or protections.",
            remediation="Implement CSRF tokens for all state-changing operations. Use synchronizer token pattern or double-submit cookie pattern. Set SameSite cookie attribute to 'Strict' or 'Lax'. Verify Origin/Referer headers. Use framework-provided CSRF protection.",
            cwe_id="CWE-352",
            cvss_score=6.5 if severity == Severity.HIGH else 4.3,
        )
