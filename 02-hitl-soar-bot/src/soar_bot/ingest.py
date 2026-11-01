"""Alert intake: authenticate, then normalise heterogeneous alert formats.

Accepted shapes
---------------
* Generic SOAR JSON: ``{"id", "title", "severity", "source", "description", "source_ip", "host", "timestamp"}``
* ECS alerts / chain summaries from Project 01 (``event.kind == "alert"``), so the
  SIEM can forward straight to this bot.
* Plain text (first line becomes the title).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

SEVERITIES = ("low", "medium", "high", "critical")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$")
SIGNATURE_MAX_SKEW_S = 300


class AlertError(ValueError):
    """Raised when an incoming alert cannot be understood."""


@dataclass
class NormalisedAlert:
    """Common shape for every accepted alert, whatever format it arrived in."""
    title: str
    severity: str
    source: str
    detected_at: float
    external_id: str | None
    host: str | None
    indicator_ip: str | None
    description: str


def sign_body(secret: str, body: bytes, timestamp: int | None = None) -> tuple[str, str]:
    """Return (timestamp, signature) headers for an outbound alert. Used by senders and tests."""
    ts = str(timestamp if timestamp is not None else int(time.time()))
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return ts, f"sha256={mac}"


def verify_body(secret: str, body: bytes, timestamp: str | None, signature: str | None,
                now: float | None = None) -> bool:
    """Verify ``X-SOAR-Timestamp`` / ``X-SOAR-Signature``. The timestamp is signed, which blocks replays."""
    if not secret or not timestamp or not signature or not signature.startswith("sha256="):
        return False
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    if abs((now or time.time()) - ts) > SIGNATURE_MAX_SKEW_S:
        return False
    expected = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature[len("sha256="):])


def _severity(value: Any) -> str:
    if isinstance(value, (int, float)):
        # ECS event.severity (Elastic 21/47/73/99 scale)
        return "critical" if value >= 90 else "high" if value >= 70 else "medium" if value >= 40 else "low"
    text = str(value or "").strip().lower()
    aliases = {"crit": "critical", "sev1": "critical", "p1": "critical", "sev2": "high", "p2": "high",
               "med": "medium", "moderate": "medium", "info": "low", "informational": "low"}
    text = aliases.get(text, text)
    return text if text in SEVERITIES else "medium"


def _ts(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def _valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _host(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).strip()
    return text if _HOST_RE.match(text) else None


def _get(doc: dict, dotted: str) -> Any:
    node: Any = doc
    for part in dotted.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def normalise(data: Any, received_at: float | None = None) -> NormalisedAlert:
    """Convert a raw alert into a :class:`NormalisedAlert`.

    Accepts plain text, ECS alerts and chain documents from the real-time SIEM,
    and a simple generic JSON format.

    Raises:
        AlertError: if the input is empty or not a recognised shape.
    """
    received_at = received_at or time.time()
    if isinstance(data, str):
        text = data.strip()
        if not text:
            raise AlertError("empty alert")
        ips = _IPV4_RE.findall(text)
        return NormalisedAlert(title=text.splitlines()[0][:200], severity="medium", source="text",
                               detected_at=received_at, external_id=None, host=None,
                               indicator_ip=ips[0] if ips else None, description=text[:8000])
    if not isinstance(data, dict):
        raise AlertError("alert must be a JSON object or text")

    if _get(data, "event.kind") == "alert" and "ecs" in data:
        chain = _get(data, "siem.chain") or {}
        hosts = _get(data, "related.hosts") or []
        title = _get(data, "rule.name") or "ECS alert"
        if chain:
            title = f"{title}: {chain.get('verdict', '')} ({chain.get('attack_stage', '')})".strip()
        return NormalisedAlert(
            title=str(title)[:200],
            severity=_severity(_get(data, "event.severity")),
            source=str(_get(data, "event.module") or "ecs"),
            detected_at=_ts(_get(data, "event.start")) or _ts(data.get("@timestamp")) or received_at,
            external_id=str(chain.get("id") or _get(data, "event.id") or "") or None,
            host=_host(_get(data, "host.hostname") or (hosts[0] if hosts else None)),
            indicator_ip=_valid_ip(_get(data, "source.ip")),
            description=str(data.get("message") or chain.get("summary") or "")[:8000],
        )

    title = data.get("title") or data.get("name") or data.get("rule") or "Untitled alert"
    description = data.get("description") or data.get("message") or ""
    ip = _valid_ip(data.get("source_ip") or data.get("ip"))
    if ip is None:
        found = _IPV4_RE.findall(f"{title} {description}")
        ip = found[0] if found else None
    return NormalisedAlert(
        title=str(title)[:200],
        severity=_severity(data.get("severity")),
        source=str(data.get("source") or "webhook")[:100],
        detected_at=_ts(data.get("timestamp") or data.get("detected_at")) or received_at,
        external_id=str(data["id"])[:200] if data.get("id") else None,
        host=_host(data.get("host") or data.get("hostname")),
        indicator_ip=ip,
        description=str(description)[:8000],
    )
