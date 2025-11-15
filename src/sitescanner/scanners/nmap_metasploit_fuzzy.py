"""Fuzzy matching layer between Nmap results and Metasploit modules.

Uses rapidfuzz if available, otherwise falls back to difflib.SequenceMatcher.
Also supports a small rule file (JSON) that maps product regexes to suggested severity.
"""

from __future__ import annotations

from difflib import SequenceMatcher
import json
from pathlib import Path
import re
from typing import TYPE_CHECKING, Any, cast

try:
    from rapidfuzz import fuzz
except Exception:  # pragma: no cover - optional dependency
    fuzz = None

if TYPE_CHECKING:
    from collections.abc import Iterable

    from sitescanner.runners.metasploit_runner import MetasploitExploitInfo, MetasploitRunner
    from sitescanner.scanners.nmap_models import NmapRunModel

from sitescanner.core.result import Severity


def _similarity(a: str, b: str) -> float:
    if fuzz is not None:
        # use token_set_ratio which handles tokenization and ordering well
        return float(fuzz.token_set_ratio(a, b))
    # fallback to difflib ratio scaled to 0-100
    return SequenceMatcher(None, a, b).ratio() * 100.0


def load_rules(path: Path | None = None) -> list[dict]:
    if path is None:
        path = Path(__file__).parent / "match_rules.json"
    try:
        return cast("list[dict[Any, Any]]", json.loads(path.read_text()))
    except Exception:
        return []


def match_nmap_to_msf_fuzzy(
    nmap_run: NmapRunModel,
    runner: MetasploitRunner,
    threshold: float = 65.0,
    rules_path: Path | None = None,
) -> Iterable[tuple[str, int, MetasploitExploitInfo, float, Severity]]:
    """Yield (addr, portid, exploit, score, suggested_severity).

    - score: similarity score 0-100
    - suggested_severity: Severity mapped by rules or Severity.INFO if none
    """
    rules = load_rules(rules_path)

    for host in nmap_run.hosts:
        addr = host.address
        for port in host.ports:
            if port.state != "open":
                continue

            service_name = (port.service.name if port.service is not None else "") or ""
            product = (port.service.product if port.service is not None else "") or ""
            version = (port.service.version if port.service is not None else "") or ""

            fingerprint = f"{service_name} {product} {version} {addr}".strip()

            for exploit in runner.list_exploits(fingerprint):
                name_score = _similarity(exploit.name.lower(), fingerprint.lower())
                desc_score = _similarity((exploit.description or "").lower(), fingerprint.lower())
                score = max(name_score, desc_score)
                if score < threshold:
                    continue

                # determine suggested severity from rules
                suggested = Severity.INFO
                for rule in rules:
                    try:
                        if re.search(rule.get("product_regex", ""), product, re.I):
                            suggested = Severity(rule.get("severity", "info"))
                            break
                    except Exception:
                        continue

                yield (addr, port.portid, exploit, score, suggested)
