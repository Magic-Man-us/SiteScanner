"""Optional runner using pymetasploit3 to query Metasploit RPC server.

This runner is defensive: it only attempts to import pymetasploit3 when used
and raises clear errors if the library or the RPC server is not available.
It implements the MetasploitRunner protocol but will not execute modules.
"""

from __future__ import annotations

from importlib import import_module
import logging
from typing import TYPE_CHECKING

from sitescanner.runners.metasploit_runner import MetasploitExploitInfo, MetasploitRunner

# Import pymetasploit3 lazily in __init__ to allow test monkeypatching
MsfRpcClient = None

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger(__name__)


class PymetasploitRunner(MetasploitRunner):
    """Wrapper around pymetasploit3.MsfRpcClient.

    Connection is established at init. Credentials and connection details
    are passed as arguments to avoid hidden configuration.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 55553,
        user: str | None = None,
        password: str | None = None,
        ssl: bool = False,
    ) -> None:
        # Allow tests to inject a fake client by monkeypatching sys.modules
        # before this class is instantiated. If the module-level import
        # failed, try to re-import here so test monkeypatching of
        # "pymetasploit3.msfrpc" is picked up.

        client_cls = MsfRpcClient
        if client_cls is None:
            try:  # pragma: no cover - exercised indirectly via tests
                module = import_module("pymetasploit3.msfrpc")
                client_cls = getattr(module, "MsfRpcClient", None)
            except Exception:  # pragma: no cover - defensive
                client_cls = None

        if client_cls is None:
            msg = "pymetasploit3 is required for PymetasploitRunner"
            raise RuntimeError(msg)

        if user is None or password is None:
            msg = "user and password are required to connect to msfrpcd"
            raise ValueError(msg)

        # Create client and keep reference
        try:
            self._client = client_cls(password, server=host, port=port, ssl=ssl, user=user)
        except Exception as exc:  # pragma: no cover - depends on environment
            logger.exception("Failed to connect to msfrpcd")
            msg = "Failed to connect to msfrpcd"
            raise RuntimeError(msg) from exc

    def list_exploits(self, target: str) -> Iterable[MetasploitExploitInfo]:
        """Search exploit modules by target string and return metadata.

        This method uses a simple substring search against module descriptions
        and names. It deliberately avoids executing modules.
        """
        try:
            # list_modules returns a dict of module-type -> list
            all_modules = self._client.modules
            # iterate exploit modules only
            exploit_names = all_modules.exploits
        except Exception:
            return []  # type: ignore[return-value]

        for name in exploit_names:
            try:
                info = self._client.get_module_options(name)
            except Exception:
                # Some modules may not be queryable; skip
                continue

            desc = info.get("description") or ""
            if target in name or target in desc:
                yield MetasploitExploitInfo(
                    name=name, description=desc, references=info.get("references") or []
                )
