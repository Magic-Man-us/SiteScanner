"""Nmap runner abstraction and concrete implementations.

Provides a Subprocess runner (calls system nmap) and a Mock runner for tests.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Protocol


class NmapRunner(Protocol):
    def run(self, target: str, args: list[str], timeout: int | None = None) -> tuple[int, str, str]:
        """Run nmap for the given target and arguments.

        Returns: (returncode, stdout, stderr)
        """
        ...


class SubprocessNmapRunner:
    """Runner that invokes the system `nmap` binary via subprocess.

    This runner is safe by using shell=False and passing args as a list.
    """

    def __init__(self, nmap_path: str | None = None) -> None:
        self._nmap = nmap_path or shutil.which("nmap")
        if not self._nmap:
            msg = "nmap binary not found on PATH"
            raise FileNotFoundError(msg)

    def run(self, target: str, args: list[str], timeout: int | None = None) -> tuple[int, str, str]:
        cmd = [str(x) for x in [self._nmap, *args, target]]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.returncode, proc.stdout, proc.stderr


class MockNmapRunner:
    """Mock runner returns pre-canned XML output for unit tests."""

    def __init__(self, xml_output: str, returncode: int = 0) -> None:
        self._xml = xml_output
        self._returncode = returncode

    def run(self, target: str, args: list[str], timeout: int | None = None) -> tuple[int, str, str]:
        # ignore target/args for the mock; return canned output
        return self._returncode, self._xml, ""
