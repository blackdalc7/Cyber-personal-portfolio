"""Alert ingestion and normalisation.

Accepts a JSON array, an object with an ``alerts`` array, or NDJSON. Each record may be:

* generic SIEM JSON: ``{"id", "timestamp", "rule", "severity", "src_ip", "dst_ip", "dst_port", ...}``
* ECS alerts (Project 01 output, Elastic): ``rule.name``, ``source.ip``, ``destination.ip`` ...
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SEVERITIES = ("informational", "low", "medium", "high", "critical")
_SEV_ALIASES = {"info": "informational", "med": "medium", "moderate": "medium", "crit": "critical",
                "1": "low", "2": "medium", "3": "high", "4": "critical"}


class AlertFormatError(ValueError):
    """Raised when an alert file or record cannot be understood."""


@dataclass(frozen=True)
class Alert:
    """One SIEM alert, normalised from any of the supported input shapes."""
    id: str
    timestamp: datetime
    rule: str
    category: str
    severity: str
    src_ip: str
    dst_ip: str
    dst_port: int | None
    protocol: str
    signature: str
    sensor: str = ""
    label: str = ""                     # ground truth, only present in simulated datasets
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @property
    def severity_rank(self) -> int:
        """Position of the severity in ``SEVERITIES`` (higher is more severe)."""
        return SEVERITIES.index(self.severity)


def _get(doc: Mapping[str, Any], dotted: str) -> Any:
    if dotted in doc:
        return doc[dotted]
    node: Any = doc
    for part in dotted.split("."):
        if not isinstance(node, Mapping):
            return None
        node = node.get(part)
    return node


def _first(doc: Mapping[str, Any], *keys: str) -> Any:
    for k in keys:
        v = _get(doc, k)
        if v not in (None, ""):
            return v
    return None


def _severity(value: Any) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 4:
        # ECS event.severity on the Elastic 21/47/73/99 scale
        return "critical" if value >= 90 else "high" if value >= 70 else "medium" if value >= 40 else "low"
    text = str(value if value is not None else "medium").strip().lower()
    text = _SEV_ALIASES.get(text, text)
    return text if text in SEVERITIES else "medium"


def _ip(value: Any) -> str:
    if value in (None, ""):
        return ""
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return ""


def _time(value: Any) -> datetime:
    if value is None:
        raise AlertFormatError("alert has no timestamp")
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise AlertFormatError(f"unparseable timestamp {value!r}") from exc
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def normalise(doc: Mapping[str, Any]) -> Alert:
    """Convert one alert record (flat, ECS-style or Suricata-style JSON) into an :class:`Alert`.

    Raises:
        AlertFormatError: if the record has no rule name or holds invalid values.
    """
    if not isinstance(doc, Mapping):
        raise AlertFormatError("each alert must be a JSON object")
    rule = _first(doc, "rule", "rule.name", "rule_name", "alert.signature", "name", "title")
    if not rule:
        raise AlertFormatError("alert has no rule name")
    if isinstance(rule, Mapping):
        rule = rule.get("name") or ""
    port = _first(doc, "dst_port", "destination.port", "dest_port")
    try:
        dst_port = int(port) if port not in (None, "") else None
    except (TypeError, ValueError):
        dst_port = None
    if dst_port is not None and not 0 <= dst_port <= 65535:
        dst_port = None
    ts = _time(_first(doc, "timestamp", "@timestamp", "event.start", "time"))
    src = _ip(_first(doc, "src_ip", "source.ip", "src"))
    dst = _ip(_first(doc, "dst_ip", "destination.ip", "dest_ip", "dst"))
    alert_id = _first(doc, "id", "event.id", "alert_id")
    if not alert_id:
        basis = json.dumps([str(rule), ts.isoformat(), src, dst, dst_port], sort_keys=True)
        alert_id = hashlib.sha256(basis.encode()).hexdigest()[:16]
    return Alert(
        id=str(alert_id), timestamp=ts, rule=str(rule)[:300],
        category=str(_first(doc, "category", "rule.category", "event.category") or "uncategorised")[:100],
        severity=_severity(_first(doc, "severity", "event.severity", "alert.severity")),
        src_ip=src, dst_ip=dst, dst_port=dst_port,
        protocol=str(_first(doc, "protocol", "network.transport", "proto") or "").lower()[:16],
        signature=str(_first(doc, "signature", "message", "rule.description", "description") or rule)[:1000],
        sensor=str(_first(doc, "sensor", "observer.name", "agent.name", "host.hostname") or "")[:100],
        label=str(_first(doc, "label", "_label") or ""), raw=doc,
    )


def load_alerts(path: str | Path) -> list[Alert]:
    """Load alerts from a JSON array, an object with an ``alerts`` key, or NDJSON.

    Raises:
        AlertFormatError: naming the record that failed to parse.
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8-sig").strip()
    if not text:
        return []
    records: list[Any]
    if text[0] in "[{":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None          # probably NDJSON
        if isinstance(data, list):
            records = data
        elif isinstance(data, Mapping) and isinstance(data.get("alerts"), list):
            records = data["alerts"]
        elif isinstance(data, Mapping):
            records = [data]
        else:
            records = []
            for n, line in enumerate(text.splitlines(), start=1):
                if line.strip():
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError as exc:
                        raise AlertFormatError(f"{path}:{n}: invalid JSON ({exc.msg})") from exc
    else:
        raise AlertFormatError(f"{path}: expected JSON or NDJSON")
    alerts = []
    for i, rec in enumerate(records):
        try:
            alerts.append(normalise(rec))
        except AlertFormatError as exc:
            raise AlertFormatError(f"{path}: record {i}: {exc}") from exc
    alerts.sort(key=lambda a: (a.timestamp, a.id))
    return alerts
