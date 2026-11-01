"""Guard rails that run before any technique executes.

A live run needs all of: an explicit ``--confirm-lab`` flag, every WinRM/SSH target given as an IP literal inside
``LAB_ALLOWED_CIDRS``, and every kubectl context named in ``LAB_KUBE_CONTEXTS`` *and* pointing at an API server
inside the lab CIDRs. Anything else is refused before a single command is sent.
"""

from __future__ import annotations

import ipaddress
import subprocess
from collections.abc import Callable
from urllib.parse import urlsplit

from .campaign import LIVE_EXECUTORS, Campaign
from .config import Settings


class SafetyError(RuntimeError):
    """The campaign is not allowed to run as configured."""


def _in_lab(ip: str, settings: Settings) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in settings.allowed_cidrs)


def kube_server(context: str) -> str:
    """The API server URL a kubectl context points at."""
    out = subprocess.run(  # noqa: S603 - fixed argv, context validated against the allowlist first
        ["kubectl", "config", "view", "--minify", "--context", context, "-o",  # noqa: S607
         "jsonpath={.clusters[0].cluster.server}"],
        capture_output=True, text=True, timeout=15, check=False)
    if out.returncode != 0:
        raise SafetyError(f"kubectl context {context!r}: {out.stderr.strip() or 'not found'}")
    return out.stdout.strip()


def check_campaign(campaign: Campaign, settings: Settings, *, confirm: bool,
                   server_of: Callable[[str], str] = kube_server) -> list[str]:
    """Raise :class:`SafetyError` if the campaign may not run; return human-readable notes otherwise."""
    notes: list[str] = []
    live = [t for t in campaign.targets.values() if t.executor in LIVE_EXECUTORS]
    if live and not confirm:
        raise SafetyError("this campaign executes real techniques on lab machines: re-run with --confirm-lab "
                          "after checking every target is a disposable lab VM (or use --dry-run)")
    for t in live:
        if t.executor in ("winrm", "ssh"):
            if not t.address or not _in_lab(t.address, settings):
                raise SafetyError(f"target {t.name}: address {t.address!r} must be an IP inside "
                                  f"{', '.join(map(str, settings.allowed_cidrs))}")
            notes.append(f"{t.name}: {t.executor} to {t.address} (inside lab CIDRs)")
        else:
            ctx = t.kube_context or ""
            if ctx not in settings.kube_contexts:
                raise SafetyError(f"target {t.name}: kube context {ctx!r} is not in LAB_KUBE_CONTEXTS")
            host = urlsplit(server_of(ctx)).hostname or ""
            if not _in_lab(host, settings):
                raise SafetyError(f"target {t.name}: context {ctx!r} points at {host!r}, outside the lab CIDRs")
            notes.append(f"{t.name}: kubectl context {ctx} -> {host} (inside lab CIDRs)")
    return notes
