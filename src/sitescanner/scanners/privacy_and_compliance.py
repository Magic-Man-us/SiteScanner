from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from pydantic import BaseModel, Field

from sitescanner.core.result import Severity, Vulnerability
from sitescanner.http import AiohttpAdapter

if TYPE_CHECKING:
    import aiohttp

    from sitescanner.http import HTTPClientProtocol, SimpleResponse

logger = logging.getLogger(__name__)


class PrivacyCheckCase(BaseModel):
    url: str
    response_headers: dict[str, str] = Field(default_factory=dict)
    html: str | None = None


class PrivacyAndComplianceScanner:
    """Combined scanner for privacy, compliance and extra security checks.

    Accepts an object implementing `HTTPClientProtocol` for requests. This makes
    the scanner easy to test with `MockClient` from `sitescanner.http`.
    """

    def __init__(self, client: HTTPClientProtocol | None = None) -> None:
        self.client = client

    async def scan_pages(
        self, pages: list[str], session: aiohttp.ClientSession
    ) -> list[Vulnerability]:
        vulnerabilities: list[Vulnerability] = []

        tasks = [self._scan_page(page, session) for page in pages]
        results = await __import__("asyncio").gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, list):
                vulnerabilities.extend(res)
            elif isinstance(res, Exception):
                logger.error("Error in privacy scanner (one of the page scans failed): %s", res)

        return vulnerabilities

    async def _scan_page(self, url: str, session: aiohttp.ClientSession) -> list[Vulnerability]:
        vulnerabilities: list[Vulnerability] = []

        try:
            robots_vulns = await self._check_robots(url, session)
            vulnerabilities.extend(robots_vulns)

            client = self.client
            if client is None:
                client = AiohttpAdapter(session)

            resp: SimpleResponse = await client.get(url)
            headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
            body = resp.body

            case = PrivacyCheckCase(url=url, response_headers=headers, html=body)

            csp_header = headers.get("content-security-policy")
            if csp_header:
                vulnerabilities.extend(self._analyze_csp(csp_header, case))

            set_cookie = headers.get("set-cookie")
            if set_cookie:
                vulnerabilities.extend(self._analyze_cookies(set_cookie, case))

            vulnerabilities.extend(self._headers_audit(headers, case))
            vulnerabilities.extend(self._gdpr_pci_heuristics(body, headers, case))
            vulnerabilities.extend(self._analyze_external_content(body, case))

        except Exception as e:
            logger.debug("Privacy scanner error for %s: %s", url, e)

        return vulnerabilities

    async def _check_robots(
        self, page_url: str, session: aiohttp.ClientSession
    ) -> list[Vulnerability]:
        vulnerabilities: list[Vulnerability] = []
        robots_url = urljoin(page_url, "/robots.txt")

        try:
            client = self.client
            if client is None:
                client = AiohttpAdapter(session)

            resp = await client.get(robots_url)
            if resp.status != 200:
                return []
            txt = resp.body

            if re.search(r"User-agent:\s*GPTBot", txt, re.I) and re.search(
                r"Disallow:\s*/", txt, re.I
            ):
                vulnerabilities.append(
                    Vulnerability(
                        vuln_type="Robots.txt: GPTBot Block",
                        severity=Severity.INFO,
                        url=robots_url,
                        parameter=None,
                        payload=None,
                        evidence="Found Disallow rule for GPTBot in robots.txt",
                        description=(
                            "Robots.txt disallows GPTBot which may prevent some crawlers from indexing content."
                        ),
                        remediation="Review robots.txt rules for desired crawler behaviour.",
                        cwe_id=None,
                        cvss_score=0.0,
                    )
                )

            if re.search(r"User-agent:\s*\*\s*Allow:\s*/", txt, re.I | re.M):
                vulnerabilities.append(
                    Vulnerability(
                        vuln_type="Robots.txt: Overly Permissive",
                        severity=Severity.LOW,
                        url=robots_url,
                        parameter=None,
                        payload=None,
                        evidence="Found 'User-agent: * Allow: /' in robots.txt",
                        description=(
                            "Robots rules allow all crawlers full access which may aid large-scale scraping."
                        ),
                        remediation=(
                            "Tighten robots.txt rules or implement server-side protections against scraping."
                        ),
                        cwe_id=None,
                        cvss_score=0.0,
                    )
                )

        except Exception:
            return []

        return vulnerabilities

    def _analyze_csp(self, csp_header: str, case: PrivacyCheckCase) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        if "unsafe-inline" in csp_header:
            vulns.append(
                Vulnerability(
                    vuln_type="CSP Weakness",
                    severity=Severity.MEDIUM,
                    url=case.url,
                    parameter=None,
                    payload=None,
                    evidence="CSP contains 'unsafe-inline'",
                    description="Content-Security-Policy allows 'unsafe-inline' which weakens protection against XSS.",
                    remediation="Avoid 'unsafe-inline', use nonces or strong hashes for inline content.",
                    cwe_id=None,
                    cvss_score=0.0,
                )
            )
        if "*" in csp_header:
            vulns.append(
                Vulnerability(
                    vuln_type="CSP Wildcard Source",
                    severity=Severity.LOW,
                    url=case.url,
                    parameter=None,
                    payload=None,
                    evidence="CSP contains wildcard '*' source",
                    description="CSP contains wildcard sources which may allow resources from untrusted origins.",
                    remediation="Restrict CSP directives to explicit origins or 'self'.",
                    cwe_id=None,
                    cvss_score=0.0,
                )
            )
        if "frame-ancestors" not in csp_header:
            vulns.append(
                Vulnerability(
                    vuln_type="CSP Missing frame-ancestors",
                    severity=Severity.LOW,
                    url=case.url,
                    parameter=None,
                    payload=None,
                    evidence="CSP missing 'frame-ancestors' directive",
                    description=(
                        "Missing 'frame-ancestors' means the site may be embeddable in other pages, increasing clickjacking risk."
                    ),
                    remediation="Add frame-ancestors 'self' or explicit origins to the CSP.",
                    cwe_id=None,
                    cvss_score=0.0,
                )
            )
        if "report-uri" not in csp_header and "report-to" not in csp_header:
            vulns.append(
                Vulnerability(
                    vuln_type="CSP No Reporting",
                    severity=Severity.INFO,
                    url=case.url,
                    parameter=None,
                    payload=None,
                    evidence="CSP has no report-uri or report-to",
                    description=(
                        "CSP reporting is not enabled; enabling it helps detect violations and potential issues in the wild."
                    ),
                    remediation="Consider adding a report-uri or report-to endpoint for CSP violation reports.",
                    cwe_id=None,
                    cvss_score=0.0,
                )
            )
        return vulns

    def _analyze_cookies(
        self, set_cookie_header: str, case: PrivacyCheckCase
    ) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        cookies = (
            set_cookie_header.split("\n") if "\n" in set_cookie_header else [set_cookie_header]
        )
        for cookie in cookies:
            if "secure" not in cookie.lower():
                vulns.append(
                    Vulnerability(
                        vuln_type="Cookie Missing Secure",
                        severity=Severity.MEDIUM,
                        url=case.url,
                        parameter=None,
                        payload=None,
                        evidence=f"Set-Cookie header without Secure flag: {cookie[:100]}",
                        description="Cookies should be set with 'Secure' to prevent transmission over HTTP.",
                        remediation="Set 'Secure' flag on cookies to ensure they are only sent over HTTPS.",
                        cwe_id=None,
                        cvss_score=0.0,
                    )
                )
            if "httponly" not in cookie.lower():
                vulns.append(
                    Vulnerability(
                        vuln_type="Cookie Missing HttpOnly",
                        severity=Severity.LOW,
                        url=case.url,
                        parameter=None,
                        payload=None,
                        evidence=f"Set-Cookie header without HttpOnly flag: {cookie[:100]}",
                        description="HttpOnly prevents JavaScript from accessing cookie values; useful for mitigating XSS data theft.",
                        remediation="Set 'HttpOnly' on session cookies where appropriate.",
                        cwe_id=None,
                        cvss_score=0.0,
                    )
                )
        return vulns

    def _analyze_external_content(self, html: str, case: PrivacyCheckCase) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            tags = soup.find_all(["script", "img", "iframe", "link"])
            for tag in tags:
                src = tag.get("src") or tag.get("href")
                if src and isinstance(src, str) and src.startswith("http") and case.url not in src:
                    vulns.append(
                        Vulnerability(
                            vuln_type="External Content",
                            severity=Severity.INFO,
                            url=case.url,
                            parameter=None,
                            payload=None,
                            evidence=f"External resource loaded: {src}",
                            description="External resources can introduce privacy and security risks depending on their origin and integrity.",
                            remediation="Review and prefer self-hosted resources or use Subresource Integrity (SRI) and minimal permissions.",
                            cwe_id=None,
                            cvss_score=0.0,
                        )
                    )
        except Exception:
            return []
        return vulns

    def _headers_audit(
        self, headers: dict[str, str], case: PrivacyCheckCase
    ) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        if "strict-transport-security" not in headers:
            vulns.append(
                Vulnerability(
                    vuln_type="Missing HSTS",
                    severity=Severity.MEDIUM,
                    url=case.url,
                    parameter=None,
                    payload=None,
                    evidence="Strict-Transport-Security header not present",
                    description="HSTS ensures browsers only access the site over HTTPS.",
                    remediation="Add a Strict-Transport-Security header with an appropriate max-age and includeSubDomains if needed.",
                    cwe_id=None,
                    cvss_score=0.0,
                )
            )

        if (
            "x-content-type-options" not in headers
            or headers.get("x-content-type-options", "").lower() != "nosniff"
        ):
            vulns.append(
                Vulnerability(
                    vuln_type="Missing X-Content-Type-Options",
                    severity=Severity.LOW,
                    url=case.url,
                    parameter=None,
                    payload=None,
                    evidence="X-Content-Type-Options missing or not 'nosniff'",
                    description="Prevents MIME-type sniffing which can cause XSS under some conditions.",
                    remediation="Set X-Content-Type-Options: nosniff.",
                    cwe_id=None,
                    cvss_score=0.0,
                )
            )

        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            vulns.append(
                Vulnerability(
                    vuln_type="Missing Frame Protection",
                    severity=Severity.LOW,
                    url=case.url,
                    parameter=None,
                    payload=None,
                    evidence="No X-Frame-Options or CSP frame-ancestors detected",
                    description="The site may be vulnerable to clickjacking if no frame restrictions are present.",
                    remediation="Add X-Frame-Options: DENY or use CSP frame-ancestors.",
                    cwe_id=None,
                    cvss_score=0.0,
                )
            )
        return vulns

    def _gdpr_pci_heuristics(
        self, html: str, headers: dict[str, str], case: PrivacyCheckCase
    ) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        if html:
            soup = BeautifulSoup(html, "html.parser")
            links = [a.get("href", "") for a in soup.find_all("a")]
            if not any("privacy" in str(href or "").lower() for href in links):
                vulns.append(
                    Vulnerability(
                        vuln_type="Missing Privacy Policy Link",
                        severity=Severity.INFO,
                        url=case.url,
                        parameter=None,
                        payload=None,
                        evidence="No link with 'privacy' found on the page",
                        description="Sites handling personal data should link to a privacy policy to satisfy GDPR transparency requirements.",
                        remediation="Add a clear link to your privacy policy.",
                        cwe_id=None,
                        cvss_score=0.0,
                    )
                )

            forms = soup.find_all("form")
            for form in forms:
                inputs = [
                    str(i.get("name") or "")
                    for i in form.find_all(["input", "textarea"])
                    if i.get("name")
                ]
                if any("card" in name.lower() or "cc" in name.lower() for name in inputs):
                    vulns.append(
                        Vulnerability(
                            vuln_type="Potential PCI Data Collection",
                            severity=Severity.MEDIUM,
                            url=case.url,
                            parameter=None,
                            payload=None,
                            evidence=f"Form appears to collect payment/card information: inputs={inputs}",
                            description="Pages that collect card data need to follow PCI DSS; ensure secure transmission and handling.",
                            remediation="Use PCI-compliant payment processors and ensure forms are transmitted over TLS.",
                            cwe_id=None,
                            cvss_score=0.0,
                        )
                    )

        cookie_consent = headers.get("set-cookie") or ""
        if (
            "consent" not in cookie_consent.lower()
            and html
            and "cookie" not in (html or "").lower()
        ):
            vulns.append(
                Vulnerability(
                    vuln_type="Missing Cookie Consent",
                    severity=Severity.INFO,
                    url=case.url,
                    parameter=None,
                    payload=None,
                    evidence="No obvious cookie consent mechanism detected",
                    description="GDPR may require explicit consent for certain cookies; consider adding a consent mechanism.",
                    remediation="Implement cookie consent where needed and document cookie usage in the privacy policy.",
                    cwe_id=None,
                    cvss_score=0.0,
                )
            )

        return vulns

    def _dnssec_placeholder(self, hostname: str, case: PrivacyCheckCase) -> list[Vulnerability]:
        return []

    def _discovered_subdomains_placeholder(
        self, hostname: str, case: PrivacyCheckCase
    ) -> list[Vulnerability]:
        return []
