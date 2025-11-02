"""Test configuration and fixtures for SiteScanner5000."""

from unittest.mock import AsyncMock

import aiohttp
import pytest


@pytest.fixture
def mock_session():
    """Create a mock aiohttp ClientSession."""
    session = AsyncMock(spec=aiohttp.ClientSession)
    return session


@pytest.fixture
def sample_html():
    """Sample HTML page for testing."""
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Test Page</title></head>
    <body>
        <form method="POST" action="/submit">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="submit" value="Login" />
        </form>
        <a href="/page1">Page 1</a>
        <a href="/page2">Page 2</a>
    </body>
    </html>
    """


@pytest.fixture
def vulnerable_sql_response():
    """Sample response indicating SQL injection vulnerability."""
    return """
    <html>
    <body>
        <h1>Database Error</h1>
        <p>You have an error in your SQL syntax near '1'='1'</p>
    </body>
    </html>
    """


@pytest.fixture
def xss_reflected_response():
    """Sample response with reflected XSS."""
    return """
    <html>
    <body>
        <p>Search results for: <script>alert('XSS')</script></p>
    </body>
    </html>
    """
