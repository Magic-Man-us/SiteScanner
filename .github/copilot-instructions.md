<!-- Project-specific instructions for GitHub Copilot -->

# SiteScanner5000 - Security Vulnerability Scanner

## Project Overview
Automated security scanner for web applications that identifies common vulnerabilities including SQL injection, XSS, CSRF, and misconfigurations. Built with Python and integrates with CI/CD pipelines.

## Development Guidelines

### Code Style
- Follow PEP 8, PEP 257, PEP 484
- Use built-in generics: list[str], dict[str, int] (PEP 585)
- Use PEP 604 union syntax: str | None instead of Optional[str]
- Use f-strings for string formatting
- Prefer async/await for IO-bound operations

### Type Hints
- Annotate all public functions and class attributes
- Use Pydantic v2 models for input validation and API boundaries
- Prefer Protocol and TypedDict where appropriate

### Security Best Practices
- Never eval/exec untrusted input
- Sanitize all external data
- Validate URLs and input parameters before scanning
- Use secrets module for sensitive data
- Avoid shell=True in subprocess calls

### Testing
- Write pytest tests for all scanner modules
- Use hypothesis for property-based testing where applicable
- Mock external HTTP requests in tests
- Aim for >80% code coverage

### Documentation
- All public functions require docstrings (PEP 257)
- Include argument types, return types, and error conditions
- Document scanner detection logic and false positive scenarios

## Project Structure
```
src/sitescanner/
├── __init__.py
├── cli.py              # Click CLI entry point
├── core/               # Core scanning engine
├── scanners/           # Individual vulnerability scanners
│   ├── sql_injection.py
│   ├── xss.py
│   ├── csrf.py
│   └── config_check.py
├── reporters/          # Report generation
└── utils/              # Shared utilities
```

## Setup Checklist

- [x] Verify copilot-instructions.md file created
- [x] Get project setup information
- [x] Scaffold project structure
- [x] Customize the project with scanner modules
- [x] Install required extensions (N/A - no extensions needed)
- [x] Install dependencies (using uv)
- [x] Run tests to verify setup (13/13 tests passing)
- [x] Complete documentation

## Key Dependencies
- requests: HTTP client for web scanning
- beautifulsoup4: HTML parsing
- pydantic: Data validation
- click: CLI framework
- pytest: Testing framework
- aiohttp: Async HTTP requests
