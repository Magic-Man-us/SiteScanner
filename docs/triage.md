# Nmap triage helper (safe-by-default)

This document explains the small Nmap -> Metasploit triage helper included with SiteScanner5000.
It is intentionally conservative and safe-by-default: the triage flow only suggests potential Metasploit
modules that might match discovered services. It never executes exploit modules.

## Quick usage

Dry-run (uses the bundled XML fixture):

```bash
python scripts/nmap_triage.py --target 192.0.2.1
```

Run the CLI subcommand (dry-run):

```bash
PYTHONPATH=src python -m sitescanner.cli nmap-triage --target 192.0.2.1
```

JSON output (machine-readable):

```bash
python scripts/nmap_triage.py --target 192.0.2.1 --format json
PYTHONPATH=src python -m sitescanner.cli nmap-triage --target 192.0.2.1 --format json
```

Run system `nmap` (explicit, ensure permission):

```bash
python scripts/nmap_triage.py --target example.com --use-nmap
PYTHONPATH=src python -m sitescanner.cli nmap-triage --target example.com --use-nmap
```

Use Metasploit RPC for metadata (opt-in and guarded):

1. Export the guard variable and credentials:

```bash
export MSF_RPC_ENABLED=true
export MSF_RPC_USER='your_user'
export MSF_RPC_PASSWORD='your_password'
export MSF_RPC_HOST='127.0.0.1'   # optional
export MSF_RPC_PORT='55553'      # optional
export MSF_RPC_SSL='false'       # optional
```

2. Run the CLI or script with `--use-msfrpc`:

```bash
PYTHONPATH=src python -m sitescanner.cli nmap-triage --target 192.0.2.1 --use-msfrpc --format json
```

Notes:
- The tool only queries exploit metadata via msfrpcd; it does not run exploits.
- Keep `MSF_RPC_ENABLED` unset or `false` in CI and in developer environments unless you intentionally want live queries.

## Match rules

Triage suggestions use a small rule file `src/sitescanner/scanners/match_rules.json` which maps product regexes to a suggested severity. Review and expand this file carefully based on your operational experience.

## Testing

Unit tests use mocked clients and fixtures. Do not enable `--use-nmap` or `--use-msfrpc` in CI.

## Security & legal

Always ensure you have explicit permission to scan targets with `nmap` or to query msfrpcd. Use the guarded opt-in and credential environment variables to avoid accidental scans.
