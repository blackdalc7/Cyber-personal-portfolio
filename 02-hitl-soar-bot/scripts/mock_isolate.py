#!/usr/bin/env python3
"""Mock host-isolation remediation (stands in for an EDR "network contain" API call).

It performs no network changes. It records the containment in a JSON state file
(the "EDR console") and prints the firewall rules a real playbook would push,
so the HitL flow can be demonstrated and tested end to end with a real
subprocess boundary.

Contract (what the SOAR bot relies on):
* arguments are validated strictly; anything unexpected exits 2
* stdout is a single JSON object
* exit 0 = isolated, 1 = remediation failed, 2 = bad input

    python scripts/mock_isolate.py --incident INC-1 --host web01 --ip 203.0.113.66 --state-file data/isolation.json
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path

HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$")
INCIDENT_RE = re.compile(r"^INC-\d{8}-[0-9A-F]{8}$")


def fail(code: int, message: str) -> int:
    """Print a JSON failure result and return ``code`` as the exit status."""
    print(json.dumps({"ok": False, "error": message}))
    return code


def atomic_write(path: Path, data: dict) -> None:
    """Write ``data`` as JSON to ``path`` via a temp file and rename, so readers never see a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".isolation-")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, path)


def main(argv: list[str] | None = None) -> int:
    """Record a simulated isolation in the state file and print a JSON result for the bot."""
    ap = argparse.ArgumentParser(description="Mock EDR host isolation")
    ap.add_argument("--incident", required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--ip", default="")
    ap.add_argument("--state-file", required=True, type=Path)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--simulate-failure", action="store_true", help="exercise the failure path")
    args = ap.parse_args(argv)

    if not INCIDENT_RE.match(args.incident):
        return fail(2, "invalid incident id")
    if not HOST_RE.match(args.host):
        return fail(2, "invalid host name")
    if args.ip:
        try:
            ipaddress.ip_address(args.ip)
        except ValueError:
            return fail(2, "invalid ip")
    if args.simulate_failure:
        return fail(1, "EDR API returned 503 (simulated)")

    rules = [f"edr-contain --host {args.host} --allow-mgmt-only"]
    if args.ip:
        rules.append(f"nft add rule inet filter input ip saddr {args.ip} drop")
        rules.append(f"nft add rule inet filter output ip daddr {args.ip} drop")
    record = {"incident": args.incident, "host": args.host, "attacker_ip": args.ip or None,
              "isolated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "rules": rules,
              "dry_run": args.dry_run}
    if not args.dry_run:
        state = {}
        if args.state_file.exists():
            try:
                state = json.loads(args.state_file.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                return fail(1, "isolation state file is corrupt")
        state.setdefault("isolated_hosts", {})[args.host] = record
        atomic_write(args.state_file, state)
    print(json.dumps({"ok": True, **record}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
