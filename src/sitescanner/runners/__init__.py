"""Runners package: external-tool runner abstractions and mocks.

This package contains runner adapters for external tools (nmap, metasploit
RPC, etc). Runners are kept separate from scanners to improve organization
and make it straightforward to add other tooling adapters.
"""

from .metasploit_runner import MetasploitExploitInfo, MetasploitRunner, MockMetasploitRunner
from .nmap_runner import MockNmapRunner, NmapRunner, SubprocessNmapRunner

__all__ = [
    "MetasploitExploitInfo",
    "MetasploitRunner",
    "MockMetasploitRunner",
    "MockNmapRunner",
    "NmapRunner",
    "SubprocessNmapRunner",
]
