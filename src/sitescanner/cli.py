"""Command-line interface for SiteScanner5000."""

import asyncio
import json
import logging
from pathlib import Path
import sys

import click
from pydantic import HttpUrl, ValidationError

from sitescanner import __version__
from sitescanner.core.result import ScanResult, Severity
from sitescanner.core.scanner import ScanConfig, Scanner


def setup_logging(verbose: bool) -> None:
    """Configure logging based on verbosity level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


@click.group()
@click.version_option(version=__version__)
def cli() -> None:
    """SiteScanner5000 - Automated Security Vulnerability Scanner.

    Scan web applications for common security vulnerabilities including
    SQL injection, XSS, CSRF, and security misconfigurations.
    """


@cli.command()
@click.argument("target", type=str)
@click.option(
    "--depth",
    "-d",
    default=3,
    type=int,
    help="Maximum crawl depth (default: 3)",
    show_default=True,
)
@click.option(
    "--max-pages",
    "-p",
    default=100,
    type=int,
    help="Maximum pages to scan (default: 100)",
    show_default=True,
)
@click.option(
    "--timeout",
    "-t",
    default=30,
    type=int,
    help="Request timeout in seconds (default: 30)",
    show_default=True,
)
@click.option(
    "--concurrent",
    "-c",
    default=5,
    type=int,
    help="Number of concurrent requests (default: 5)",
    show_default=True,
)
@click.option(
    "--scanners",
    "-s",
    multiple=True,
    type=click.Choice(["sql_injection", "xss", "csrf", "config"], case_sensitive=False),
    help="Specific scanners to run (default: all)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file for scan results (JSON format)",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "text"], case_sensitive=False),
    default="text",
    help="Output format (default: text)",
    show_default=True,
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose logging",
)
def scan(
    target: str,
    depth: int,
    max_pages: int,
    timeout: int,
    concurrent: int,
    scanners: tuple[str, ...],
    output: Path | None,
    format: str,
    verbose: bool,
) -> None:
    """Scan a target URL for security vulnerabilities.

    TARGET: The URL to scan (e.g., https://example.com)
    """
    setup_logging(verbose)

    try:
        # Validate target URL
        try:
            validated_target = HttpUrl(target)
        except ValidationError:
            click.echo(f"Error: Invalid URL format: {target}", err=True)
            sys.exit(1)

        # Build scan configuration with Pydantic validation
        enabled_scanners = (
            list(scanners) if scanners else ["sql_injection", "xss", "csrf", "config"]
        )

        config = ScanConfig(
            target=validated_target,
            max_depth=depth,
            max_pages=max_pages,
            timeout=timeout,
            concurrent_requests=concurrent,
            enabled_scanners=enabled_scanners,
        )

        click.echo(f"Starting scan of {config.target}")
        click.echo(f"Enabled scanners: {', '.join(config.enabled_scanners)}")

        # Run scan
        result = asyncio.run(run_scan(config))

        # Output results
        if format == "json":
            output_json(result, output)
        else:
            output_text(result, output)

        # Exit with appropriate code
        critical_count = len(result.get_by_severity(Severity.CRITICAL))
        high_count = len(result.get_by_severity(Severity.HIGH))

        if critical_count > 0:
            sys.exit(2)  # Critical vulnerabilities found
        elif high_count > 0:
            sys.exit(1)  # High severity vulnerabilities found
        else:
            sys.exit(0)  # Success

    except KeyboardInterrupt:
        click.echo("\nScan interrupted by user", err=True)
        sys.exit(130)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        if verbose:
            raise
        sys.exit(1)


async def run_scan(config: ScanConfig) -> ScanResult:
    """Execute the security scan asynchronously.

    Args:
        config: Validated scan configuration

    Returns:
        Complete scan results
    """
    async with Scanner(config) as scanner:
        return await scanner.scan()


def output_json(result: ScanResult, output_path: Path | None) -> None:
    """Output scan results in JSON format.

    Args:
        result: Scan results
        output_path: Optional file path to write results
    """
    json_data = result.model_dump(mode="json")
    json_str = json.dumps(json_data, indent=2)

    if output_path:
        output_path.write_text(json_str)
        click.echo(f"Results written to {output_path}")
    else:
        click.echo(json_str)


def output_text(result: ScanResult, output_path: Path | None) -> None:
    """Output scan results in human-readable text format.

    Args:
        result: Scan results
        output_path: Optional file path to write results
    """
    lines: list[str] = []

    lines.append("=" * 80)
    lines.append("SECURITY SCAN REPORT")
    lines.append("=" * 80)
    lines.append(f"Target: {result.target}")
    lines.append(f"Scan ID: {result.scan_id}")
    lines.append(f"Start Time: {result.start_time}")
    lines.append(
        f"Duration: {result.scan_duration:.2f}s" if result.scan_duration else "Duration: N/A"
    )
    lines.append(f"Pages Scanned: {result.pages_scanned}")
    lines.append("")

    # Summary
    lines.append("VULNERABILITY SUMMARY")
    lines.append("-" * 80)
    summary = result.summary()
    for severity_name, count in summary.items():
        lines.append(f"  {severity_name.upper():12} {count}")
    lines.append("")

    # Detailed vulnerabilities
    if result.vulnerabilities:
        lines.append("DETAILED FINDINGS")
        lines.append("-" * 80)

        for i, vuln in enumerate(result.vulnerabilities, 1):
            lines.append(f"\n[{i}] {vuln.vuln_type} - {vuln.severity.value.upper()}")
            lines.append(f"    URL: {vuln.url}")
            if vuln.parameter:
                lines.append(f"    Parameter: {vuln.parameter}")
            if vuln.payload:
                lines.append(f"    Payload: {vuln.payload}")
            lines.append(f"    Description: {vuln.description}")
            lines.append(f"    Remediation: {vuln.remediation}")
            if vuln.cwe_id:
                lines.append(f"    CWE: {vuln.cwe_id}")
            if vuln.cvss_score:
                lines.append(f"    CVSS Score: {vuln.cvss_score}")
    else:
        lines.append("No vulnerabilities detected! 🎉")

    lines.append("")
    lines.append("=" * 80)

    output_str = "\n".join(lines)

    if output_path:
        output_path.write_text(output_str)
        click.echo(f"Results written to {output_path}")
    else:
        click.echo(output_str)


@cli.command()
def version() -> None:
    """Display version information."""
    click.echo(f"SiteScanner5000 version {__version__}")


if __name__ == "__main__":
    cli()
