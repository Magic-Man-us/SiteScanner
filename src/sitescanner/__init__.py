"""SiteScanner5000 - Automated Security Vulnerability Scanner.

A comprehensive web application security scanner that identifies common
vulnerabilities including SQL injection, XSS, CSRF, and misconfigurations.
"""

__version__ = "0.1.0"
__author__ = "SiteScanner5000 Team"

from sitescanner.core.result import ScanResult, Vulnerability
from sitescanner.core.scanner import Scanner

__all__ = ["ScanResult", "Scanner", "Vulnerability"]
