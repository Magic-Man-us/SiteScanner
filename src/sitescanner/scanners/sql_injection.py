"""SQL Injection vulnerability scanner with Pydantic validation."""

import asyncio
import logging
from typing import TYPE_CHECKING
from urllib.parse import ParseResult, parse_qs, urlencode, urlparse, urlunparse

import aiohttp
from pydantic import BaseModel, Field, field_validator

if TYPE_CHECKING:
    pass

from sitescanner.core.result import Severity, Vulnerability

logger = logging.getLogger(__name__)


class SQLInjectionPayload(BaseModel):
    """Pydantic model for SQL injection test payloads."""

    payload: str = Field(..., min_length=1, description="SQL injection test string")
    description: str = Field(..., description="What this payload tests for")
    error_indicators: list[str] = Field(
        default_factory=list, description="Error strings that indicate vulnerability"
    )

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, v: str) -> str:
        """Ensure payload is not empty or whitespace only."""
        if not v.strip():
            raise ValueError("Payload cannot be empty or whitespace")
        return v


class SQLInjectionTestCase(BaseModel):
    """Pydantic model for a SQL injection test case."""

    url: str  # Allow string URLs for internal use
    parameter: str = Field(..., min_length=1)
    original_value: str
    test_payload: SQLInjectionPayload
    response_time: float | None = None
    response_code: int | None = None
    response_body: str | None = None


class SQLInjectionScanner:
    """Scanner for SQL injection vulnerabilities using Pydantic models."""

    # Common SQL injection payloads with Pydantic validation
    PAYLOADS = [
        SQLInjectionPayload(
            payload="' OR '1'='1",
            description="Classic SQL injection bypass",
            error_indicators=[
                "sql syntax",
                "mysql_fetch",
                "pg_query",
                "sqlite3",
                "odbc_exec",
            ],
        ),
        SQLInjectionPayload(
            payload="' OR 1=1--",
            description="Comment-based SQL injection",
            error_indicators=[
                "syntax error",
                "mysql error",
                "warning: mysql",
                "unclosed quotation",
            ],
        ),
        SQLInjectionPayload(
            payload="1' AND '1'='2",
            description="Boolean-based blind SQL injection",
            error_indicators=["sql", "mysql", "postgres", "oracle", "microsoft"],
        ),
        SQLInjectionPayload(
            payload="'; DROP TABLE users--",
            description="Destructive SQL injection test",
            error_indicators=["syntax", "near", "drop"],
        ),
        SQLInjectionPayload(
            payload="1' UNION SELECT NULL--",
            description="UNION-based SQL injection",
            error_indicators=["union", "syntax", "the used select statements"],
        ),
        SQLInjectionPayload(
            payload="' WAITFOR DELAY '00:00:05'--",
            description="Time-based blind SQL injection",
            error_indicators=["waitfor", "timeout"],
        ),
    ]

    async def scan_pages(
        self, pages: list[str], session: aiohttp.ClientSession
    ) -> list[Vulnerability]:
        """Scan multiple pages for SQL injection vulnerabilities.

        Args:
            pages: List of URLs to scan
            session: aiohttp session for making requests

        Returns:
            List of detected SQL injection vulnerabilities
        """
        vulnerabilities: list[Vulnerability] = []

        tasks = [self._scan_page(page, session) for page in pages]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                vulnerabilities.extend(result)
            elif isinstance(result, Exception):
                logger.error(f"Error scanning page: {result}")

        return vulnerabilities

    async def _scan_page(self, url: str, session: aiohttp.ClientSession) -> list[Vulnerability]:
        """Scan a single page for SQL injection vulnerabilities.

        Args:
            url: Target URL to scan
            session: aiohttp session for making requests

        Returns:
            List of detected vulnerabilities on this page
        """
        vulnerabilities: list[Vulnerability] = []

        # Parse URL and extract parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulnerabilities

        # Test each parameter with each payload
        for param_name, param_values in params.items():
            for payload_model in self.PAYLOADS:
                try:
                    # Create test case with Pydantic validation
                    test_case = SQLInjectionTestCase(
                        url=url,
                        parameter=param_name,
                        original_value=param_values[0] if param_values else "",
                        test_payload=payload_model,
                    )

                    vuln = await self._test_parameter(test_case, session, parsed, params)
                    if vuln:
                        vulnerabilities.append(vuln)

                except Exception as e:
                    logger.debug(f"Error testing {param_name} with {payload_model.payload}: {e}")

        return vulnerabilities

    async def _test_parameter(
        self,
        test_case: SQLInjectionTestCase,
        session: aiohttp.ClientSession,
        parsed_url: ParseResult,
        original_params: dict[str, list[str]],
    ) -> Vulnerability | None:
        """Test a parameter for SQL injection vulnerability.

        Args:
            test_case: Pydantic-validated test case
            session: aiohttp session
            parsed_url: Parsed URL tuple
            original_params: Original query parameters

        Returns:
            Vulnerability if detected, None otherwise
        """
        # Create modified parameters with payload
        test_params = original_params.copy()
        test_params[test_case.parameter] = [test_case.test_payload.payload]

        # Rebuild URL with injected payload
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
                test_case.response_body = body[:1000]  # Limit stored body size

                # Check for SQL error indicators in response
                body_lower = body.lower()
                for indicator in test_case.test_payload.error_indicators:
                    if indicator.lower() in body_lower:
                        return Vulnerability(
                            vuln_type="SQL Injection",
                            severity=Severity.CRITICAL,
                            url=test_case.url,
                            parameter=test_case.parameter,
                            payload=test_case.test_payload.payload,
                            evidence=f"SQL error indicator '{indicator}' found in response",
                            description=f"SQL injection vulnerability detected in parameter '{test_case.parameter}'. {test_case.test_payload.description}",
                            remediation="Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries. Implement input validation and use ORM frameworks.",
                            cwe_id="CWE-89",
                            cvss_score=9.8,
                        )

        except Exception as e:
            logger.debug(f"Request failed for {test_url}: {e}")

        return None
