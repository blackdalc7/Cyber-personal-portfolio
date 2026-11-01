"""Runs the remediation script in a subprocess, only after a recorded human approval.

Security properties
-------------------
* argv list, never ``shell=True``: alert fields cannot inject shell syntax
* host/IP validated again here (defence in depth; the script validates too)
* hard timeout, so a hung EDR call cannot pin a worker forever
* minimal environment: the child does not inherit the bot's secrets
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$")


@dataclass
class RemediationResult:
    """Outcome of one isolation attempt: success flag, exit code, parsed JSON output and stderr."""
    ok: bool
    exit_code: int
    output: dict
    stderr: str


class Remediator:
    """Run the isolation script as a subprocess, with strict argument validation.

    The host name and IP are validated before use and passed as separate argv
    items (never through a shell), so alert content cannot inject commands.
    """
    def __init__(self, script: Path, state_file: Path, timeout_s: int = 60, dry_run: bool = False,
                 extra_args: list[str] | None = None) -> None:
        self.script = Path(script)
        self.state_file = Path(state_file)
        self.timeout = timeout_s
        self.dry_run = dry_run
        self.extra_args = extra_args or []

    def isolate(self, incident_id: str, host: str | None, ip: str | None) -> RemediationResult:
        """Isolate ``host`` for ``incident_id`` and return the script's result.

        Invalid input or a missing script returns a failed result instead of raising.
        """
        if not host or not HOST_RE.match(host):
            return RemediationResult(False, 2, {"error": "no valid host to isolate"}, "")
        if ip:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return RemediationResult(False, 2, {"error": "invalid ip"}, "")
        if not self.script.is_file():
            return RemediationResult(False, 127, {"error": f"remediation script not found: {self.script}"}, "")
        argv = [sys.executable, str(self.script), "--incident", incident_id, "--host", host,
                "--state-file", str(self.state_file)]
        if ip:
            argv += ["--ip", ip]
        if self.dry_run:
            argv.append("--dry-run")
        argv += self.extra_args
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONIOENCODING": "utf-8"}
        if os.name == "nt":
            env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout, env=env,  # noqa: S603 - fixed argv, validated args
                                  check=False)
        except subprocess.TimeoutExpired:
            return RemediationResult(False, -1, {"error": f"timed out after {self.timeout}s"}, "")
        try:
            output = json.loads(proc.stdout.strip().splitlines()[-1]) if proc.stdout.strip() else {}
        except (ValueError, IndexError):
            output = {"raw_stdout": proc.stdout[-2000:]}
        return RemediationResult(proc.returncode == 0 and bool(output.get("ok")), proc.returncode, output,
                                 proc.stderr[-2000:])
