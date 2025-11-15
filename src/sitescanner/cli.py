"""Command-line interface for SiteScanner5000."""

import asyncio
import json
import logging
import os
from pathlib import Path
import sys

import click
from pydantic import HttpUrl, ValidationError

from sitescanner import __version__
from sitescanner.core.result import ScanResult, Severity
from sitescanner.core.scanner import ScanConfig, Scanner
from sitescanner.runners.metasploit_runner import (
    MetasploitExploitInfo,
    MetasploitRunner,
    MockMetasploitRunner,
)
from sitescanner.runners.nmap_runner import SubprocessNmapRunner
from sitescanner.scanners.nmap_metasploit_fuzzy import match_nmap_to_msf_fuzzy
from sitescanner.scanners.nmap_models import NmapRunModel
from sitescanner.scanners.nmap_scanner import NmapScanner

# Optional import: keep at module-level but guarded so the CLI doesn't require
# the heavy optional dependency unless the operator requests msfrpc usage.
try:  # pragma: no cover - optional dependency
    from sitescanner.scanners.pymetasploit_runner import PymetasploitRunner
except Exception:  # pragma: no cover - optional dependency
    _PymetasploitRunner = None


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
    type=click.Choice(["sql_injection", "xss", "csrf", "config", "privacy"], case_sensitive=False),
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
            list(scanners) if scanners else ["sql_injection", "xss", "csrf", "config", "privacy"]
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


@cli.command(name="nmap-triage")
@click.option("--target", required=True, help="Target host or IP")
@click.option("--use-nmap", is_flag=True, help="Run real nmap (requires nmap binary)")
@click.option("--rules", type=click.Path(), default=None, help="Path to JSON match rules")
@click.option("--threshold", type=float, default=65.0, help="Similarity threshold (0-100)")
@click.option(
    "--use-msfrpc",
    is_flag=True,
    help="If set, attempt to use pymetasploit3 + msfrpcd (requires env MSF_RPC_ENABLED=true)",
)
@click.option(
    "--format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    help="Output format for triage results",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def nmap_triage(
    target: str,
    use_nmap: bool,
    rules: str | None,
    threshold: float,
    use_msfrpc: bool,
    format: str,
    verbose: bool,
) -> None:
    """Run Nmap (or fixture) and fuzzy-match results to potential Metasploit modules.

    This command is safe by default: without ``--use-nmap`` it uses a bundled
    XML fixture. The command never executes exploit modules; it only suggests
    potential matches for manual triage.
    """
    setup_logging(verbose)

    try:
        nmap_run = _load_nmap_run(target=target, use_nmap=use_nmap)
        msf_runner = _build_msf_runner(use_msfrpc=use_msfrpc, verbose=verbose)

        click.echo("Matching nmap results to exploit modules...")
        matches = list(
            match_nmap_to_msf_fuzzy(
                nmap_run,
                msf_runner,
                threshold=threshold,
                rules_path=Path(rules) if rules else None,
            )
        )

        _print_nmap_triage_results(matches=matches, output_format=format)

    except KeyboardInterrupt as exc:
        click.echo("\nInterrupted by user", err=True)
        raise SystemExit(130) from exc
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        if verbose:
            raise
        raise SystemExit(1) from exc


if __name__ == "__main__":
    cli()


def _load_nmap_run(target: str, use_nmap: bool) -> NmapRunModel:
    """Load Nmap results either by executing nmap or from a fixture file."""

    if use_nmap:
        runner = SubprocessNmapRunner()
        scanner = NmapScanner(runner=runner)
        click.echo("Running nmap (ensure you have permission to scan the target)")
        retcode, stdout, stderr = runner.run(target, scanner.flags)
        if retcode != 0:
            click.echo(f"nmap failed: {stderr}", err=True)
            raise SystemExit(2)
        return NmapRunModel.from_xml(stdout)

    fixture = Path("tests/fixtures/nmap/sample1.xml")
    if not fixture.exists():
        click.echo("Sample fixture not found; run from project root", err=True)
        raise SystemExit(1)
    xml = fixture.read_text()
    return NmapRunModel.from_xml(xml)


def _build_msf_runner(use_msfrpc: bool, verbose: bool) -> MetasploitRunner:
    """Construct a Metasploit runner based on CLI flags and environment.

    Returns a concrete runner instance; falls back to a mock runner when
    msfrpc usage is disabled or unavailable.
    """

    msf_runner: MetasploitRunner | None = None

    if use_msfrpc:
        if os.environ.get("MSF_RPC_ENABLED", "false").lower() != "true":
            click.echo(
                "MSF RPC usage is disabled by default. Set MSF_RPC_ENABLED=true to enable.",
                err=True,
            )
            raise SystemExit(2)

        if _PymetasploitRunner is None:
            msg = "pymetasploit3 is not installed or PymetasploitRunner unavailable"
            raise RuntimeError(msg)

        try:  # type: ignore[unreachable]
            msf_host = os.environ.get("MSF_RPC_HOST", "127.0.0.1")
            msf_port = int(os.environ.get("MSF_RPC_PORT", "55553"))
            msf_user = os.environ.get("MSF_RPC_USER")
            msf_pass = os.environ.get("MSF_RPC_PASSWORD")
            msf_ssl = os.environ.get("MSF_RPC_SSL", "false").lower() == "true"

            msf_runner = PymetasploitRunner(
                host=msf_host,
                port=msf_port,
                user=msf_user,
                password=msf_pass,
                ssl=msf_ssl,
            )
        except Exception as exc:  # pragma: no cover - network/env dependent
            click.echo(f"Failed to initialize msfrpc runner: {exc}", err=True)
            if verbose:
                raise
            raise SystemExit(2) from exc

    if msf_runner is None:
        demo_exploits = [
            MetasploitExploitInfo(name="exploit/linux/nginx_fake", description="nginx RCE"),
        ]
        msf_runner = MockMetasploitRunner(exploits=demo_exploits)

    return msf_runner


def _print_nmap_triage_results(
    matches: list[tuple[str, int, MetasploitExploitInfo, float, Severity]], output_format: str
) -> None:
    """Pretty-print nmap / Metasploit triage results to the console."""

    if output_format == "json":
        out = []
        for addr, portid, exploit, score, severity in matches:
            out.append(
                {
                    "addr": addr,
                    "port": portid,
                    "exploit": {
                        "name": exploit.name,
                        "description": exploit.description,
                    },
                    "score": score,
                    "suggested_severity": severity.value,
                }
            )
        click.echo(json.dumps(out, indent=2))
        return

    any_found = False
    for addr, portid, exploit, score, severity in matches:
        any_found = True
        click.echo(
            f"{addr}:{portid} -> {exploit.name} (score={score:.1f}) suggested={severity.value}"
        )

    if not any_found:
        click.echo("No matches above threshold found.")
