"""Shim module: re-export Metasploit runner types from `sitescanner.runners`.

This keeps the historical import path `sitescanner.scanners.metasploit_runner`
while the canonical implementation lives in `sitescanner.runners`.
"""

from sitescanner.runners.metasploit_runner import (
    MetasploitExploitInfo,
    MetasploitRunner,
    MockMetasploitRunner,
)

__all__ = ["MetasploitExploitInfo", "MetasploitRunner", "MockMetasploitRunner"]
