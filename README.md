# SiteScanner5000

[![CI (uv)](https://github.com/Magic-Man-us/SiteScanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Magic-Man-us/SiteScanner/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
[![Code style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type checked: mypy](https://img.shields.io/badge/type%20checked-mypy-blue.svg)](http://mypy-lang.org/)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![Security: safety](https://img.shields.io/badge/security-safety-blue.svg)](https://github.com/pyupio/safety)

**Automated Security Vulnerability Scanner for Web Applications**

SiteScanner5000 is a comprehensive security scanning tool that identifies common vulnerabilities in web applications, including SQL injection, Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), and security misconfigurations.

## Features

**Security Scanners**
- SQL Injection Detection: Identifies SQL injection vulnerabilities with multiple payload variations
- XSS Scanner: Detects reflected, stored, and DOM-based XSS vulnerabilities (7 payload types)
- CSRF Protection Check: Validates CSRF token implementations and cookie security
- Configuration Scanner: Checks security headers, TLS/HTTPS configuration, and information disclosure

**Performance & Quality**
- Async/Concurrent Scanning: Fast scanning with configurable concurrent requests using aiohttp
- Type-Safe: Full type hints with mypy validation
- Pydantic v2 Validation: Robust data validation for all models and payloads
- Comprehensive Testing: pytest with asyncio support, >50% code coverage
- Pre-commit Hooks: Automated code quality checks (Ruff, Black, mypy)

**Developer Experience**
- Multiple Output Formats: JSON and human-readable text reports
- CLI Interface: Easy-to-use Click-based command-line tool
- CI/CD Integration: GitHub Actions workflow with security scanning
- Modern Python: Built with Python 3.11-3.14, using uv for blazing-fast dependency management

## Installation

### Prerequisites

Install [uv](https://docs.astral.sh/uv/) - the fast Python package installer:

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"

# Or with pip (if you must)
pip install uv
```

### From Source

```bash
# Clone the repository
git clone https://github.com/Magic-Man-us/SiteScanner.git
cd SiteScanner

# Install dependencies with uv (fast!)
uv sync --all-extras
```

### Using uv (recommended)

```bash
# Add SiteScanner to your project
uv add sitescanner5000
```

## Quick Start

### Basic Scan

```bash
# Scan a target URL
uv run sitescanner scan https://example.com

# Scan with specific scanners only
uv run sitescanner scan https://example.com -s sql_injection -s xss

# Save results to file
uv run sitescanner scan https://example.com -o results.json --format json
```

### Advanced Usage

```bash
# Custom scan depth and concurrency
uv run sitescanner scan https://example.com \
    --depth 5 \
    --max-pages 200 \
    --concurrent 10 \
    --timeout 60

# Verbose output for debugging
uv run sitescanner scan https://example.com -v

# Scan specific areas
uv run sitescanner scan https://example.com \
    -s config \
    -o security-headers.txt
```

## Configuration Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--depth` | `-d` | Maximum crawl depth | 3 |
| `--max-pages` | `-p` | Maximum pages to scan | 100 |
| `--timeout` | `-t` | Request timeout (seconds) | 30 |
| `--concurrent` | `-c` | Concurrent requests | 5 |
| `--scanners` | `-s` | Specific scanners to run | all |
| `--output` | `-o` | Output file path | stdout |
| `--format` | `-f` | Output format (json/text) | text |
| `--verbose` | `-v` | Enable verbose logging | false |

## Available Scanners

- **sql_injection**: SQL injection vulnerability detection
- **xss**: Cross-Site Scripting detection
- **csrf**: CSRF protection validation
- **config**: Security configuration and headers check

## Programmatic Usage

```python
import asyncio
from sitescanner.core.scanner import Scanner, ScanConfig

async def main():
    config = ScanConfig(
        target="https://example.com",
        max_depth=3,
        enabled_scanners=["sql_injection", "xss"],
    )

    async with Scanner(config) as scanner:
        result = await scanner.scan()

    print(f"Found {len(result.vulnerabilities)} vulnerabilities")
    for vuln in result.vulnerabilities:
        print(f"- {vuln.vuln_type}: {vuln.severity}")

asyncio.run(main())
```

## Development

### Setup Development Environment

```bash
# Install all dependencies including dev tools (with uv - fast!)
uv sync --all-extras

# Install pre-commit hooks for automated quality checks
pre-commit install

# Pre-commit will now run automatically on git commit
# Or run manually on all files:
pre-commit run --all-files
```

### Running Tests

```bash
# Run all tests
uv run pytest

# Run tests with coverage report
uv run pytest --cov=sitescanner --cov-report=html
open htmlcov/index.html  # View coverage report

# Run specific test file
uv run pytest tests/test_sql_injection.py

# Run tests matching a pattern
uv run pytest -k "test_sql"

# Run with verbose output
uv run pytest -v --showlocals
```

### Code Quality Checks

```bash
# Run all checks (automatically runs on git commit via pre-commit)
uv run ruff check .           # Linting
uv run ruff format --check .  # Format checking
uv run mypy src/              # Type checking

# Auto-fix issues
uv run ruff check --fix .
uv run ruff format .

# Run security scans
uv run bandit -r src/
uv run safety check
```

### Development Workflow

1. **Make changes** to code
2. **Run tests**: `uv run pytest`
3. **Commit**: Pre-commit hooks will automatically run Ruff, Black, and mypy
4. **Push**: CI/CD will run full test suite on Python 3.11-3.14

### Project Structure

```
SiteScanner5000/
├── src/sitescanner/
│   ├── __init__.py              # Package exports
│   ├── cli.py                   # Click CLI interface
│   ├── core/
│   │   ├── scanner.py           # Main async scanner orchestrator
│   │   └── result.py            # Pydantic models (Vulnerability, ScanResult)
│   └── scanners/
│       ├── sql_injection.py     # SQL injection scanner (6 payloads)
│       ├── xss.py               # XSS scanner (7 payload types)
│       ├── csrf.py              # CSRF protection validator
│       └── config_check.py      # Security headers & TLS checker
├── tests/
│   ├── conftest.py              # Pytest fixtures
│   ├── test_core.py             # Core model tests
│   ├── test_sql_injection.py   # SQL injection tests
│   └── test_xss.py              # XSS scanner tests
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions CI/CD (uv-based)
├── .pre-commit-config.yaml      # Pre-commit hooks config
├── pyproject.toml               # Project metadata, dependencies, tool config
├── uv.lock                      # uv lockfile for reproducible builds
├── README.md
└── PRE_COMMIT_SETUP.md          # Pre-commit usage guide
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Install uv
  uses: astral-sh/setup-uv@v4
  with:
    enable-cache: true

- name: Set up Python
  run: uv python install 3.11

- name: Install SiteScanner
  run: uv add sitescanner5000

- name: Security Scan
  run: |
    uv run sitescanner scan ${{ secrets.TARGET_URL }} --output scan-results.json --format json

- name: Check for Critical Vulnerabilities
  run: |
    # Exit code 2 = critical vulnerabilities found
    # Exit code 1 = high severity vulnerabilities
    # Exit code 0 = no critical/high issues
    uv run sitescanner scan ${{ secrets.TARGET_URL }}
```

## Exit Codes

- `0`: Scan completed successfully, no critical/high vulnerabilities
- `1`: High severity vulnerabilities detected
- `2`: Critical vulnerabilities detected
- `130`: Scan interrupted by user
- Other: Error occurred during scan

## Security Considerations

**WARNING**: Only scan applications you have permission to test. Unauthorized security scanning may be illegal in your jurisdiction.

- Always get written permission before scanning
- Use responsibly in compliance with laws and regulations
- Be aware that some payloads may trigger security systems or cause application issues
- Consider using in a staging/test environment first

## Contributing

Contributions are welcome! We follow modern Python best practices.

### How to Contribute

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/YOUR-USERNAME/SiteScanner.git`
3. **Create a feature branch**: `git checkout -b feature/amazing-feature`
4. **Install dependencies**: `uv sync --all-extras`
5. **Install pre-commit hooks**: `pre-commit install`
6. **Make your changes** with tests
7. **Run tests**: `uv run pytest`
8. **Commit**: Pre-commit hooks will validate your code automatically
9. **Push**: `git push origin feature/amazing-feature`
10. **Open a Pull Request**

### Code Standards

- All code must pass Ruff, Black, and mypy checks
- Write tests for new features (pytest)
- Use Pydantic models for data validation
- Add type hints to all functions
- Follow PEP 8, PEP 257 (docstrings), PEP 484 (type hints)
- Use async/await for IO-bound operations
- Update documentation as needed

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Tech Stack

### Core Technologies
- **[Python 3.11-3.14](https://www.python.org/)**: Modern Python with latest features
- **[uv](https://docs.astral.sh/uv/)**: Blazing-fast package management (10-100x faster than pip)
- **[Pydantic v2](https://docs.pydantic.dev/)**: Data validation with type hints
- **[aiohttp](https://docs.aiohttp.org/)**: Async HTTP client for concurrent requests
- **[Click](https://click.palletsprojects.com/)**: Command-line interface framework
- **[BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/)**: HTML parsing

### Development Tools
- **[Ruff](https://github.com/astral-sh/ruff)**: Fast Python linter (30+ rule categories)
- **[Black](https://github.com/psf/black)**: Uncompromising code formatter
- **[mypy](http://mypy-lang.org/)**: Static type checker
- **[pytest](https://pytest.org/)**: Testing framework with asyncio support
- **[pre-commit](https://pre-commit.com/)**: Git hooks for automated quality checks
- **[Bandit](https://bandit.readthedocs.io/)**: Security vulnerability scanner
- **[Safety](https://pyup.io/safety/)**: Dependency vulnerability checker

### Build System
- **[Hatchling](https://hatch.pypa.io/)**: Modern Python build backend

## Support & Resources

- [Documentation](https://github.com/Magic-Man-us/SiteScanner#readme)
- [Issue Tracker](https://github.com/Magic-Man-us/SiteScanner/issues)
- [Discussions](https://github.com/Magic-Man-us/SiteScanner/discussions)
- [Changelog](https://github.com/Magic-Man-us/SiteScanner/releases)
- [CI/CD Status](https://github.com/Magic-Man-us/SiteScanner/actions)

## Roadmap

Future enhancements planned:

- [ ] Additional scanners (file upload, auth bypass, XXE, SSRF)
- [ ] Page crawling and discovery
- [ ] HTML report generation
- [ ] Integration with vulnerability databases (CVE, OWASP Top 10)
- [ ] Plugin system for custom scanners
- [ ] Interactive mode with TUI
- [ ] Docker image for containerized scanning
- [ ] API server mode

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

### Legal Disclaimer

**This tool is for educational and authorized security testing purposes only.**

- Only scan applications you have **explicit written permission** to test
- Unauthorized security scanning may be **illegal** in your jurisdiction
- Users are **solely responsible** for ensuring compliance with all applicable laws
- Some payloads may trigger security systems or cause application issues
- **Always test in staging/test environments first**

By using this tool, you acknowledge that you understand and accept these terms.
