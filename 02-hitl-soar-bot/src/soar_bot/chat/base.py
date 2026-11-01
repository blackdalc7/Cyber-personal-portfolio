"""Shared interface and formatting helpers for the chat providers (Slack, Discord, outbox)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol

from ..db import Incident

SEVERITY_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}

APPROVE = "approve"
REJECT = "reject"


class ChatError(RuntimeError):
    """Raised when a chat API call fails after retries."""


class ChatProvider(Protocol):
    """Interface every chat backend implements."""
    name: str

    def send_approval_request(self, incident: Incident) -> tuple[str, str]:
        """Post the interactive card. Returns (channel, message_ref)."""

    def update(self, incident: Incident) -> None:
        """Replace the card with the incident's current status (buttons removed once decided)."""


def fmt_ts(epoch: float | None) -> str:
    """Format an epoch timestamp as a UTC string, or ``-`` when it is ``None``."""
    if epoch is None:
        return "-"
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def action_value(incident: Incident) -> str:
    """Opaque button payload: incident id plus the per-incident approval nonce."""
    return f"{incident.id}:{incident.approval_nonce}"


def parse_action_value(value: str) -> tuple[str, str]:
    """Split a button value ``<incident_id>:<nonce>`` into its two parts.

    Raises:
        ValueError: if either part is missing.
    """
    incident_id, _, nonce = (value or "").partition(":")
    if not incident_id or not nonce:
        raise ValueError("malformed action value")
    return incident_id, nonce


def status_line(incident: Incident) -> str:
    """One-line, human-readable status shown at the bottom of the approval card."""
    s = incident.status
    who = incident.decided_by or "unknown"
    if s == "awaiting_approval":
        return "⏳ Awaiting analyst approval"
    if s == "approved":
        return f"✅ Approved by {who} at {fmt_ts(incident.decided_at)}; queuing isolation"
    if s == "remediating":
        return f"⚙️ Approved by {who}; isolation in progress"
    if s == "remediated":
        return (f"🛡️ Host isolated. Approved by {who} at {fmt_ts(incident.decided_at)}, "
                f"contained at {fmt_ts(incident.resolved_at)}")
    if s == "failed":
        return f"❌ Isolation FAILED after approval by {who}; manual action required"
    if s == "rejected":
        return f"🚫 Isolation rejected by {who} at {fmt_ts(incident.decided_at)}"
    if s == "expired":
        return "⌛ Approval window expired with no decision; escalate to the on-call lead"
    return f"Status: {s}"


def summary_fields(incident: Incident) -> list[tuple[str, str]]:
    """Label and value pairs shown on the card: severity, risk, host, IP, intel and time."""
    abuse = (incident.enrichment or {}).get("abuseipdb") or {}
    intel = "no external intel"
    if abuse:
        intel = (f"AbuseIPDB {abuse.get('abuse_confidence')}% · {abuse.get('total_reports')} reports"
                 f" · {abuse.get('country') or '?'}{' · TOR' if abuse.get('is_tor') else ''}")
    elif (incident.enrichment or {}).get("scope") == "internal":
        intel = "internal address"
    return [
        ("Severity", f"{SEVERITY_EMOJI.get(incident.severity, '')} {incident.severity.upper()}"),
        ("Risk score", f"{incident.risk_score}/100"),
        ("Host", incident.host or "-"),
        ("Indicator IP", incident.indicator_ip or "-"),
        ("Threat intel", intel),
        ("Detected", fmt_ts(incident.detected_at)),
    ]
