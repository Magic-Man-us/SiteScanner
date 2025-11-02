"""Main scanner orchestration engine."""

import asyncio
import logging
from datetime import datetime
from uuid import uuid4

import aiohttp
from pydantic import BaseModel, Field, HttpUrl

from sitescanner.core.result import ScanResult
from sitescanner.scanners.config_check import ConfigScanner
from sitescanner.scanners.csrf import CSRFScanner
from sitescanner.scanners.sql_injection import SQLInjectionScanner
from sitescanner.scanners.xss import XSSScanner

logger = logging.getLogger(__name__)


class ScanConfig(BaseModel):
    """Configuration for a security scan."""

    target: HttpUrl
    max_depth: int = Field(default=3, ge=1, le=10)
    max_pages: int = Field(default=100, ge=1, le=1000)
    timeout: int = Field(default=30, ge=5, le=120)
    follow_redirects: bool = True
    user_agent: str = "SiteScanner5000/0.1.0"
    concurrent_requests: int = Field(default=5, ge=1, le=20)
    enabled_scanners: list[str] = Field(
        default_factory=lambda: ["sql_injection", "xss", "csrf", "config"]
    )


class Scanner:
    """Main scanner orchestrator for running vulnerability scans."""

    def __init__(self, config: ScanConfig) -> None:
        """Initialize scanner with configuration.

        Args:
            config: Scan configuration parameters
        """
        self.config = config
        self.scan_result: ScanResult | None = None
        self._session: aiohttp.ClientSession | None = None

        # Initialize scanner modules
        self.scanners = {
            "sql_injection": SQLInjectionScanner(),
            "xss": XSSScanner(),
            "csrf": CSRFScanner(),
            "config": ConfigScanner(),
        }

    async def __aenter__(self) -> "Scanner":
        """Async context manager entry."""
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.timeout),
            headers={"User-Agent": self.config.user_agent},
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        if self._session:
            await self._session.close()

    async def scan(self) -> ScanResult:
        """Execute complete security scan.

        Returns:
            ScanResult containing all detected vulnerabilities

        Raises:
            RuntimeError: If scanner not initialized with context manager
        """
        if not self._session:
            raise RuntimeError("Scanner must be used as async context manager")

        scan_id = str(uuid4())
        start_time = datetime.now()

        logger.info(f"Starting scan {scan_id} for {self.config.target}")

        self.scan_result = ScanResult(
            target=self.config.target,
            scan_id=scan_id,
            start_time=start_time,
        )

        # Discover pages to scan
        pages = await self._discover_pages()
        logger.info(f"Discovered {len(pages)} pages to scan")

        # Run enabled scanners concurrently
        scan_tasks = []
        for scanner_name in self.config.enabled_scanners:
            if scanner_name in self.scanners:
                scanner = self.scanners[scanner_name]
                scan_tasks.append(scanner.scan_pages(pages, self._session))

        # Execute all scanner tasks concurrently
        results = await asyncio.gather(*scan_tasks, return_exceptions=False)

        # Aggregate results
        for scanner_vulns in results:
            for vuln in scanner_vulns:
                self.scan_result.add_vulnerability(vuln)

        # Finalize scan result
        end_time = datetime.now()
        self.scan_result.end_time = end_time
        self.scan_result.pages_scanned = len(pages)
        self.scan_result.scan_duration = (end_time - start_time).total_seconds()

        logger.info(
            f"Scan {scan_id} completed. Found {len(self.scan_result.vulnerabilities)} vulnerabilities"
        )

        return self.scan_result

    async def _discover_pages(self) -> list[str]:
        """Discover pages within the target domain.

        Returns:
            List of discovered page URLs
        """
        # Placeholder for page discovery logic
        # In production, this would crawl the site up to max_depth and max_pages
        return [str(self.config.target)]
