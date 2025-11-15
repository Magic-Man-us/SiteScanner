from unittest.mock import AsyncMock

import pytest

from sitescanner.http import MockClient, SimpleResponse


@pytest.fixture
def mock_session() -> AsyncMock:
    """Provide an AsyncMock to satisfy aiohttp.ClientSession signature when needed.

    Tests that use an injected `MockClient` can pass this fixture as the `session`
    argument to scanner methods; the MockClient will handle requests so the session
    is not used.
    """
    return AsyncMock()


@pytest.fixture
def simple_response_factory():
    """Return a factory to create SimpleResponse easily in tests."""

    def _factory(
        status: int = 200, headers: dict | None = None, body: str = "", cookies: dict | None = None
    ):
        return SimpleResponse(
            status=status, headers=headers or {}, body=body, cookies=cookies or {}
        )

    return _factory


@pytest.fixture
def mock_client_factory():
    """Return a factory that builds a MockClient from a mapping easily."""

    def _factory(mapping: dict[str, SimpleResponse] | None = None) -> MockClient:
        return MockClient(mapping or {})

    return _factory
