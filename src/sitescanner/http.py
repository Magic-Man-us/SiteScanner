"""Small HTTP client protocol and adapters to make scanners easier to test.

Provides:
- SimpleResponse: small container for status, headers, body
- HTTPClientProtocol: typing.Protocol for client implementations
- AiohttpAdapter: adapter for an aiohttp.ClientSession for production
- MockClient: simple mapping-based mock for tests
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    import aiohttp


@dataclass
class SimpleResponse:
    status: int
    headers: dict[str, str]
    body: str
    cookies: dict[str, dict[str, str]] | None = None


class HTTPClientProtocol(Protocol):
    async def get(
        self, url: str, **kwargs: Any
    ) -> SimpleResponse:  # pragma: no cover - thin protocol
        ...


class AiohttpAdapter:
    """Adapter that wraps an aiohttp.ClientSession and returns SimpleResponse objects."""

    def __init__(self, session: aiohttp.ClientSession) -> None:
        self._session = session

    async def get(self, url: str, **kwargs: Any) -> SimpleResponse:
        async with self._session.get(url, **kwargs) as resp:
            body = await resp.text()
            # Extract cookies into a simple mapping: name -> dict(attributes)
            cookies: dict[str, dict[str, str]] = {}
            try:
                for name, morsel in resp.cookies.items():
                    # morsel may be a Morsel; create a small dict for attributes
                    attrs = dict(morsel.items())
                    cookies[name] = {"value": morsel.value, **attrs}
            except Exception:
                cookies = {}

            return SimpleResponse(
                status=resp.status, headers=dict(resp.headers), body=body, cookies=cookies
            )


class MockClient:
    """Very small mock client for tests. Provide a mapping of url -> SimpleResponse.

    Example:
        client = MockClient({"https://example.com/robots.txt": SimpleResponse(200, {}, "User-agent: GPTBot\nDisallow: /")})
    """

    def __init__(self, mapping: dict[str, SimpleResponse] | None = None) -> None:
        self._mapping = mapping or {}

    async def get(self, url: str, **kwargs: Any) -> SimpleResponse:
        # Exact match first
        if url in self._mapping:
            return self._mapping[url]

        # Prefix match: allow tests to map base URLs (e.g. "https://example.com/page") to
        # responses that should apply to any query-string variation or injected payloads.
        for key, resp in self._mapping.items():
            if url.startswith(key):
                return resp
        # default safe empty response
        return SimpleResponse(status=200, headers={}, body="", cookies={})
