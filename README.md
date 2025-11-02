# SiteScanner5000

[![CI/CD](https://github.com/Magic-Man-us/SiteScanner/workflows/CI%2FCD/badge.svg)](https://github.com/Magic-Man-us/SiteScanner/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Automated Security Vulnerability Scanner for Web Applications**

SiteScanner5000 is a comprehensive security scanning tool that identifies common vulnerabilities in web applications, including SQL injection, Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), and security misconfigurations.

## Features

- **SQL Injection Detection**: Identifies SQL injection vulnerabilities with multiple payload variations
- **XSS Scanner**: Detects reflected, stored, and DOM-based XSS vulnerabilities
- **CSRF Protection Check**: Validates CSRF token implementations and cookie security
- **Configuration Scanner**: Checks security headers, TLS/HTTPS configuration, and information disclosure
- **Async/Concurrent Scanning**: Fast scanning with configurable concurrent requests
- **Multiple Output Formats**: JSON and human-readable text reports
- **Pydantic Validation**: Robust data validation for all models and payloads
- **CLI Interface**: Easy-to-use command-line tool
- **CI/CD Integration**: Perfect for automated security testing pipelines

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/sitescanner5000.git
cd sitescanner5000

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"
```

### Using pip (when published)

```bash
pip install sitescanner5000
```

## Quick Start

### Basic Scan

```bash
# Scan a target URL
sitescanner scan https://example.com

# Scan with specific scanners only
sitescanner scan https://example.com -s sql_injection -s xss

# Save results to file
sitescanner scan https://example.com -o results.json --format json
```

### Advanced Usage

```bash
# Custom scan depth and concurrency
sitescanner scan https://example.com \
    --depth 5 \
    --max-pages 200 \
    --concurrent 10 \
    --timeout 60

# Verbose output for debugging
sitescanner scan https://example.com -v

# Scan specific areas
sitescanner scan https://example.com \
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
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=sitescanner --cov-report=html

# Run linting
ruff check src/ tests/
black --check src/ tests/
mypy src/

# Format code
black src/ tests/
ruff check --fix src/ tests/
```

### Project Structure

```
sitescanner5000/
├── src/sitescanner/
│   ├── __init__.py
│   ├── cli.py              # CLI interface
│   ├── core/               # Core scanning engine
│   │   ├── scanner.py      # Main scanner orchestrator
│   │   └── result.py       # Result models
│   └── scanners/           # Individual scanners
│       ├── sql_injection.py
│       ├── xss.py
│       ├── csrf.py
│       └── config_check.py
├── tests/                  # Test suite
├── pyproject.toml          # Project configuration
└── README.md
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    pip install sitescanner5000
    sitescanner scan ${{ secrets.TARGET_URL }} --output scan-results.json --format json

- name: Check for Critical Vulnerabilities
  run: |
    # Exit code 2 = critical vulnerabilities found
    # Exit code 1 = high severity vulnerabilities
    # Exit code 0 = no critical/high issues
    sitescanner scan ${{ secrets.TARGET_URL }}
```

## Exit Codes

- `0`: Scan completed successfully, no critical/high vulnerabilities
- `1`: High severity vulnerabilities detected
- `2`: Critical vulnerabilities detected
- `130`: Scan interrupted by user
- Other: Error occurred during scan

## Security Considerations

⚠️ **Important**: Only scan applications you have permission to test. Unauthorized security scanning may be illegal in your jurisdiction.

- Always get written permission before scanning
- Use responsibly in compliance with laws and regulations
- Be aware that some payloads may trigger security systems or cause application issues
- Consider using in a staging/test environment first

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass and code is formatted
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

Built with:
- [Pydantic](https://docs.pydantic.dev/) for data validation
- [aiohttp](https://docs.aiohttp.org/) for async HTTP requests
- [Click](https://click.palletsprojects.com/) for CLI interface
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) for HTML parsing

## Support

- 📖 [Documentation](https://github.com/yourusername/sitescanner5000/wiki)
- 🐛 [Issue Tracker](https://github.com/yourusername/sitescanner5000/issues)
- 💬 [Discussions](https://github.com/yourusername/sitescanner5000/discussions)

---

**Disclaimer**: This tool is for educational and authorized testing purposes only. Users are responsible for ensuring they have permission to scan target applications.
