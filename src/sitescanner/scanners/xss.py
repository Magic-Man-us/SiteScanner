"""Cross-Site Scripting (XSS) vulnerability scanner with Pydantic validation.

This module provides a small, testable XSS scanner implementation. It accepts
an HTTP client implementing ``HTTPClientProtocol`` so unit tests can inject a
mock client. ``AiohttpAdapter`` is imported at module level to avoid placing
imports inside functions (which the linter flags).
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, ClassVar
from urllib.parse import ParseResult, parse_qs, urlencode, urlparse, urlunparse

from bs4 import BeautifulSoup
from pydantic import BaseModel, Field, field_validator

if TYPE_CHECKING:
    import aiohttp

from sitescanner.core.result import Severity, Vulnerability
from sitescanner.http import AiohttpAdapter, HTTPClientProtocol, SimpleResponse

logger = logging.getLogger(__name__)


class XSSPayload(BaseModel):
    payload: str = Field(..., min_length=1)
    description: str = Field(...)
    detection_patterns: list[str] = Field(default_factory=list)
    payload_type: str = Field(...)

    @field_validator("payload_type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        allowed = {"reflected", "stored", "dom"}
        if v.lower() not in allowed:
            msg = f"payload_type must be one of {allowed}"
            raise ValueError(msg)
        return v.lower()


class XSSTestCase(BaseModel):
    url: str
    parameter: str | None = None
    test_payload: XSSPayload
    response_code: int | None = None
    response_body: str | None = None
    injection_point: str = Field(...)


class XSSScanner:
    """A small XSS scanner that accepts an optional HTTP client for testing.

    If no client is supplied the scanner will instantiate and use the
    module-level AiohttpAdapter when executing HTTP requests.
    """

    def __init__(self, client: HTTPClientProtocol | None = None) -> None:
        self.client = client

    PAYLOADS: ClassVar[list[XSSPayload]] = [
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
    ]

    async def scan_pages(
        self, pages: list[str], session: aiohttp.ClientSession
    ) -> list[Vulnerability]:
        vulnerabilities: list[Vulnerability] = []
        tasks = [self._scan_page(page, session) for page in pages]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                vulnerabilities.extend(result)
            elif isinstance(result, Exception):
                logger.debug("Error scanning page for XSS: %s", result)

        return vulnerabilities

    async def _scan_page(self, url: str, session: aiohttp.ClientSession) -> list[Vulnerability]:
        vulnerabilities: list[Vulnerability] = []
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
                    except Exception:
                        logger.debug("Error testing XSS on %s", param_name)

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
        if not test_case.parameter:
            return None

        test_params = original_params.copy()
        test_params[test_case.parameter] = [test_case.test_payload.payload]
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
            client = self.client or AiohttpAdapter(session)
            resp: SimpleResponse = await client.get(test_url)
            body = resp.body
            test_case.response_code = resp.status
            test_case.response_body = body[:1000]

            for pattern in test_case.test_payload.detection_patterns:
                if pattern in body:
                    msg = f"XSS payload reflected in response. Pattern '{pattern}' found unescaped."
                    return Vulnerability(
                        vuln_type="Cross-Site Scripting (XSS)",
                        severity=Severity.HIGH,
                        url=test_case.url,
                        parameter=test_case.parameter,
                        payload=test_case.test_payload.payload,
                        evidence=msg,
                        description=f"XSS vulnerability detected in parameter '{test_case.parameter}'. {test_case.test_payload.description}.",
                        remediation="Implement output encoding/escaping and CSP headers.",
                        cwe_id="CWE-79",
                        cvss_score=7.1,
                    )
        except Exception:
            logger.debug("Request failed for %s", test_url)

        return None

    async def _scan_forms(self, url: str, session: aiohttp.ClientSession) -> list[Vulnerability]:
        vulnerabilities: list[Vulnerability] = []
        try:
            client = self.client or AiohttpAdapter(session)
            resp = await client.get(url)
            html = resp.body
            soup = BeautifulSoup(html, "html.parser")

            forms = soup.find_all("form")
            for form in forms:
                inputs = form.find_all(["input", "textarea"])
                for input_field in inputs:
                    input_name = input_field.get("name")
                    if input_name:
                        # Placeholder for additional form payload testing
                        pass
        except Exception:
            logger.debug("Error scanning forms on %s", url)

        return vulnerabilities
