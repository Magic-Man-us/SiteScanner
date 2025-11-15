"""Runner abstraction for Metasploit-like integrations.

Provides a safe protocol and a mock implementation for tests. It does NOT
attempt to run exploits or perform intrusive actions; scanners will only
query metadata (available exploit modules) and produce findings based on
matching signatures.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Iterable


class MetasploitExploitInfo:
    """Lightweight DTO describing an exploit module."""

    def __init__(self, name: str, description: str, references: list[str] | None = None) -> None:
        self.name = name
        self.description = description
        self.references = references or []


class MetasploitRunner(Protocol):
    """Protocol for querying Metasploit-like service for modules.

    Implementations may communicate via RPC, subprocess, or a library client.
    For safety, scanners should never call a method that executes an exploit
    without explicit operator confirmation.
    """

    def list_exploits(self, target: str) -> Iterable[MetasploitExploitInfo]:
        """Return exploit metadata potentially relevant to the target."""
        ...


class MockMetasploitRunner:
    """Mock runner returns pre-defined exploits for test scenarios."""

    def __init__(self, exploits: list[MetasploitExploitInfo] | None = None) -> None:
        self._exploits = exploits or []

    def list_exploits(self, target: str) -> Iterable[MetasploitExploitInfo]:
        # In the mock we simply return the predefined list. Real implementations
        # could filter by target OS/service fingerprint.
        return iter(self._exploits)
