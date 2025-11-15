Nmap scanner
============

.. warning::
   The Nmap scanner is optional and must be used responsibly. Running active
   network discovery or port scanning against systems you do not own or have
   explicit permission to test may be illegal in some jurisdictions.

Overview
--------

The project includes an opt-in Nmap-based scanner that invokes the system
`nmap` binary (via a subprocess runner) and parses the XML output into
structured Pydantic models. The scanner is intentionally not enabled by
default to avoid accidental active scans.

Key points
^^^^^^^^^^

- Opt-in only: the scanner will only run when code explicitly creates a
  ``NmapScanner`` (which uses ``SubprocessNmapRunner`` by default).
- Safe subprocess invocation: the runner uses ``shell=False`` and builds the
  argument list directly to avoid shell injection hazards.
- Mockable for tests: use ``MockNmapRunner`` and saved XML fixtures for
  deterministic, fast unit tests.

Security & legal notes
----------------------

Port scanning, service enumeration, OS fingerprinting, and related network
reconnaissance are considered intrusive operations. Before running the
Nmap scanner against any target, ensure:

- You own the target or have explicit, written permission to scan it.
- You understand and comply with local laws, organizational policies, and
  any contract terms (some cloud providers and hosting services disallow
  unsolicited scanning).
- Scans are run with appropriate operational safety (rate-limiting, times,
  monitoring, and change windows).

Recommended usage patterns
--------------------------

1. Unit tests and CI should never call the real ``nmap`` binary. Use
   ``MockNmapRunner`` with saved XML fixtures to validate parsing and
   processing logic. See the tests/fixtures directory for examples.

2. For manual or gated integration runs (admin-only), run the scanner on a
   controlled host with permission. Consider using a temporary, isolated
   environment and limit scan intensity ("--top-ports 100" or similar).

Example: running an integration scan (manual)
-------------------------------------------

Create a short Python script to run nmap via the scanner (example):

.. code-block:: python

    from sitescanner.scanners.nmap_runner import SubprocessNmapRunner
    from sitescanner.scanners.nmap_scanner import NmapScanner

    runner = SubprocessNmapRunner()
    scanner = NmapScanner(runner=runner)
    findings = scanner.scan_target("198.51.100.10")
    for f in findings:
        print(f.json())

Notes:

- The SubprocessNmapRunner will raise ``FileNotFoundError`` if ``nmap`` is
  not available on the PATH.
- Consider wrapping the runner invocation with try/except to handle
  timeouts or subprocess errors gracefully.

Testing the scanner
-------------------

Unit tests should use the ``MockNmapRunner`` to return saved XML fixtures.
Example (pytest):

.. code-block:: python

    from pathlib import Path
    from sitescanner.scanners.nmap_runner import MockNmapRunner
    from sitescanner.scanners.nmap_scanner import NmapScanner

    xml = Path("tests/fixtures/nmap/sample1.xml").read_text()
    runner = MockNmapRunner(xml_output=xml)
    scanner = NmapScanner(runner=runner)
    assert len(scanner.scan_target("192.0.2.1")) >= 1

If you want to include a gated integration test that runs real nmap scans,
mark the test with a pytest marker (for example ``@pytest.mark.integration``)
and require an environment variable (for example ``RUN_INTEGRATION=1``) so
that CI does not run it by default.

Further ideas
-------------

- Map detected product/version strings to severity levels (e.g. known-vulnerable
  versions -> MEDIUM/HIGH) using a curated signature file.
- Support parsing NSE script outputs for additional findings.

See also
--------

- ``src/sitescanner/scanners/nmap_runner.py`` — runner abstraction
- ``src/sitescanner/scanners/nmap_models.py`` — Pydantic models that parse XML
- ``src/sitescanner/scanners/nmap_scanner.py`` — scanner mapping models to Vulnerability objects
