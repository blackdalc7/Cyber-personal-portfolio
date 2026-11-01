"""Elastic Common Schema (ECS 8.11) mapping and strict validation.

Every document the SIEM writes passes through :func:`validate`, which rejects
any field that is not either a real ECS field (from the subset declared in
``ECS_FIELDS``) or a declared custom field in the ``siem.*`` namespace. That
keeps the output drop-in compatible with Elasticsearch/Kibana ECS mappings,
Elastic Security detection rules, and any other ECS consumer.
"""

from __future__ import annotations

import ipaddress
import json
import re
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from .syslog_parser import SyslogMessage

ECS_VERSION = "8.11.0"

# field -> ECS type. Only the fields this pipeline can emit are declared;
# anything else is a schema violation.
ECS_FIELDS: dict[str, str] = {
    "@timestamp": "date",
    "message": "match_only_text",
    "tags": "keyword",
    "labels": "object",
    "ecs.version": "keyword",
    # event.*
    "event.id": "keyword",
    "event.kind": "keyword",
    "event.category": "keyword",
    "event.type": "keyword",
    "event.action": "keyword",
    "event.outcome": "keyword",
    "event.code": "keyword",
    "event.module": "keyword",
    "event.dataset": "keyword",
    "event.provider": "keyword",
    "event.created": "date",
    "event.ingested": "date",
    "event.start": "date",
    "event.end": "date",
    "event.original": "keyword",
    "event.severity": "long",
    "event.risk_score": "float",
    "event.reason": "keyword",
    # log.syslog.*
    "log.syslog.priority": "long",
    "log.syslog.facility.code": "long",
    "log.syslog.facility.name": "keyword",
    "log.syslog.severity.code": "long",
    "log.syslog.severity.name": "keyword",
    "log.syslog.version": "keyword",
    "log.syslog.hostname": "keyword",
    "log.syslog.appname": "keyword",
    "log.syslog.procid": "keyword",
    "log.syslog.msgid": "keyword",
    "log.syslog.structured_data": "flattened",
    "log.level": "keyword",
    # entities
    "host.hostname": "keyword",
    "host.name": "keyword",
    "process.name": "keyword",
    "process.pid": "long",
    "process.command_line": "wildcard",
    "process.working_directory": "keyword",
    "source.ip": "ip",
    "source.port": "long",
    "user.name": "keyword",
    "user.domain": "keyword",
    "user.effective.name": "keyword",
    "user.target.name": "keyword",
    "group.name": "keyword",
    "related.ip": "ip",
    "related.user": "keyword",
    "related.hosts": "keyword",
    "observer.type": "keyword",
    "observer.vendor": "keyword",
    "observer.product": "keyword",
    "observer.hostname": "keyword",
    "network.transport": "keyword",
    "network.protocol": "keyword",
    "error.message": "match_only_text",
    # alerts
    "rule.id": "keyword",
    "rule.name": "keyword",
    "rule.description": "keyword",
    "rule.ruleset": "keyword",
    "rule.category": "keyword",
    "rule.reference": "keyword",
    "threat.framework": "keyword",
    "threat.tactic.id": "keyword",
    "threat.tactic.name": "keyword",
    "threat.technique.id": "keyword",
    "threat.technique.name": "keyword",
}

# Custom fields (ECS guidance: custom data lives in its own namespace).
CUSTOM_FIELDS: dict[str, str] = {
    "siem.alert.evidence_count": "long",
    "siem.alert.trigger_event_ids": "keyword",
    "siem.chain.id": "keyword",
    "siem.chain.alert_ids": "keyword",
    "siem.chain.alert_count": "long",
    "siem.chain.rule_ids": "keyword",
    "siem.chain.attack_stage": "keyword",
    "siem.chain.verdict": "keyword",
    "siem.chain.summary": "match_only_text",
    "siem.chain.recommended_actions": "keyword",
    "siem.chain.llm.provider": "keyword",
    "siem.chain.llm.model": "keyword",
    "siem.chain.llm.latency_ms": "long",
    "siem.chain.llm.fallback_reason": "keyword",
}

ALLOWED_FIELDS = {**ECS_FIELDS, **CUSTOM_FIELDS}

# ECS allowed values for the categorisation fields.
ALLOWED_VALUES: dict[str, set[str]] = {
    "event.kind": {"alert", "asset", "enrichment", "event", "metric", "state", "pipeline_error", "signal"},
    "event.category": {"api", "authentication", "configuration", "database", "driver", "email", "file",
                       "host", "iam", "intrusion_detection", "library", "malware", "network", "package",
                       "process", "registry", "session", "threat", "vulnerability", "web"},
    "event.type": {"access", "admin", "allowed", "change", "connection", "creation", "deletion", "denied",
                   "end", "error", "group", "indicator", "info", "installation", "protocol", "start",
                   "user"},
    "event.outcome": {"failure", "success", "unknown"},
}


class ECSValidationError(ValueError):
    """Raised when a document contains a non-ECS field or an invalid value."""


def flatten(doc: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flatten nested dicts to dotted keys. ``labels`` and SD maps stay as leaf objects."""
    out: dict[str, Any] = {}
    for key, value in doc.items():
        dotted = f"{prefix}{key}"
        if isinstance(value, dict) and dotted not in ("labels", "log.syslog.structured_data"):
            out.update(flatten(value, f"{dotted}."))
        else:
            out[dotted] = value
    return out


def _is_date(v: Any) -> bool:
    if not isinstance(v, str):
        return False
    try:
        datetime.fromisoformat(v.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def _is_ip(v: Any) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except (ValueError, TypeError):
        return False


_TYPE_CHECKS: dict[str, Callable[[Any], bool]] = {
    "date": _is_date,
    "ip": _is_ip,
    "long": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "float": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "keyword": lambda v: isinstance(v, str),
    "wildcard": lambda v: isinstance(v, str),
    "match_only_text": lambda v: isinstance(v, str),
    "flattened": lambda v: isinstance(v, dict),
    "object": lambda v: isinstance(v, dict) and all(isinstance(x, str) for x in v.values()),
}

_LABEL_KEY_RE = re.compile(r"^[a-z0-9_]+$")


def validate(doc: dict[str, Any]) -> None:
    """Raise :class:`ECSValidationError` unless ``doc`` is strictly ECS-conformant."""
    flat = flatten(doc)
    for required in ("@timestamp", "ecs.version", "event.kind"):
        if required not in flat:
            raise ECSValidationError(f"missing required field {required}")
    for key, value in flat.items():
        ftype = ALLOWED_FIELDS.get(key)
        if ftype is None:
            raise ECSValidationError(f"field {key!r} is not in ECS {ECS_VERSION} or the siem.* custom schema")
        values = value if isinstance(value, list) else [value]
        for v in values:
            if not _TYPE_CHECKS[ftype](v):
                raise ECSValidationError(f"field {key!r} expects {ftype}, got {v!r}")
        allowed = ALLOWED_VALUES.get(key)
        if allowed:
            bad = [v for v in values if v not in allowed]
            if bad:
                raise ECSValidationError(f"field {key!r} has non-ECS value(s) {bad}")
        if key == "labels" and not all(_LABEL_KEY_RE.match(k) for k in value):
            raise ECSValidationError("labels keys must match [a-z0-9_]+")


def set_path(doc: dict[str, Any], dotted: str, value: Any) -> None:
    """Assign ``value`` at a dotted path, creating nested objects. ``None`` is skipped."""
    if value is None or value == [] or value == "":
        return
    parts = dotted.split(".")
    node = doc
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def get_path(doc: dict[str, Any], dotted: str, default: Any = None) -> Any:
    """Read a dotted ECS field such as ``source.ip`` from a nested dict, or ``default`` if absent."""
    node: Any = doc
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def iso(ts: datetime) -> str:
    """Format a datetime as ECS-style UTC ISO 8601 with millisecond precision and a ``Z`` suffix."""
    return ts.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Message classification: syslog text -> ECS categorisation
# ---------------------------------------------------------------------------

_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+)"
_PORT = r"(?: port (?P<port>\d{1,5}))?"


class Rule:
    """One message-classification rule: a regex plus the ECS event fields it implies."""
    __slots__ = ("action", "category", "outcome", "pattern", "tags", "type")

    def __init__(self, pattern: str, action: str, category: list[str], type_: list[str],
                 outcome: str, tags: list[str] | None = None) -> None:
        self.pattern = re.compile(pattern)
        self.action = action
        self.category = category
        self.type = type_
        self.outcome = outcome
        self.tags = tags or []


# Order matters: the first match wins.
MESSAGE_RULES: list[Rule] = [
    Rule(rf"Failed (?:password|publickey|none) for invalid user (?P<user>\S*) from {_IP}{_PORT}",
         "ssh_login", ["authentication"], ["start"], "failure", ["invalid_user"]),
    Rule(rf"Failed (?:password|publickey|keyboard-interactive/pam|none) for (?P<user>\S+) from {_IP}{_PORT}",
         "ssh_login", ["authentication"], ["start"], "failure"),
    Rule(rf"Invalid user (?P<user>\S*) from {_IP}{_PORT}",
         "ssh_login", ["authentication"], ["start"], "failure", ["invalid_user"]),
    Rule(rf"Accepted (?:password|publickey|keyboard-interactive/pam|gssapi-with-mic) "
         rf"for (?P<user>\S+) from {_IP}{_PORT}",
         "ssh_login", ["authentication"], ["start"], "success"),
    Rule(rf"authentication failure;.*?rhost={_IP}(?:\s+user=(?P<user>\S+))?",
         "pam_authentication", ["authentication"], ["start"], "failure"),
    Rule(r"^\s*(?P<user>\S+) : (?:\d+ incorrect password attempts?|user NOT in sudoers)",
         "sudo", ["authentication"], ["start"], "failure"),
    Rule(r"^\s*(?P<user>\S+) : .*?(?:PWD=(?P<cwd>\S+) ; )?USER=(?P<euser>\S+) ; COMMAND=(?P<cmd>.+)$",
         "sudo", ["process"], ["start"], "success"),
    Rule(r"new user: name=(?P<target>[^,\s]+)",
         "user_created", ["iam"], ["user", "creation"], "success"),
    Rule(r"add '(?P<target>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'",
         "user_added_to_group", ["iam"], ["group", "change"], "success"),
    Rule(r"session opened for user (?P<user>\S+?)(?:\(uid=\d+\))?(?: by|$)",
         "session_opened", ["session"], ["start"], "success"),
    Rule(r"session closed for user (?P<user>\S+)",
         "session_closed", ["session"], ["end"], "success"),
]

# Windows Security events forwarded as JSON over syslog (NXLog / Winlogbeat to_json style).
WINDOWS_EVENTS: dict[int, tuple[str, list[str], list[str], str]] = {
    4624: ("logged-in", ["authentication"], ["start"], "success"),
    4625: ("logon-failed", ["authentication"], ["start"], "failure"),
    4672: ("logged-in-special", ["iam"], ["admin"], "success"),
    4720: ("added-user-account", ["iam"], ["user", "creation"], "success"),
    4732: ("added-member-to-group", ["iam"], ["group", "change"], "success"),
}


def _apply_windows_json(doc: dict[str, Any], msg: str) -> bool:
    try:
        data = json.loads(msg)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    try:
        event_id = int(data.get("EventID") or data.get("event_id") or data.get("Id"))
    except (TypeError, ValueError):
        return False
    mapping = WINDOWS_EVENTS.get(event_id)
    if not mapping:
        return False
    action, category, type_, outcome = mapping
    set_path(doc, "event.code", str(event_id))
    set_path(doc, "event.provider", "Microsoft-Windows-Security-Auditing")
    set_path(doc, "event.action", action)
    set_path(doc, "event.category", category)
    set_path(doc, "event.type", type_)
    set_path(doc, "event.outcome", outcome)
    host = data.get("Hostname") or data.get("Computer")
    if host:
        set_path(doc, "host.hostname", str(host))
    user = data.get("TargetUserName")
    if user and user != "-":
        set_path(doc, "user.name", str(user))
    domain = data.get("TargetDomainName")
    if domain and domain != "-":
        set_path(doc, "user.domain", str(domain))
    ip = data.get("IpAddress")
    if ip and _is_ip(ip):
        set_path(doc, "source.ip", ip)
    return True


def to_ecs(msg: SyslogMessage, peer_ip: str | None = None, peer_port: int | None = None,
           ingested_at: datetime | None = None) -> dict[str, Any]:
    """Map a parsed syslog message to a strictly-validated ECS event document."""
    ingested_at = ingested_at or datetime.now(timezone.utc)
    ts = msg.timestamp or msg.received_at
    doc: dict[str, Any] = {}
    set_path(doc, "@timestamp", iso(ts))
    set_path(doc, "ecs.version", ECS_VERSION)
    set_path(doc, "message", msg.message)
    set_path(doc, "event.id", str(uuid.uuid4()))
    set_path(doc, "event.kind", "event")
    set_path(doc, "event.module", "syslog")
    set_path(doc, "event.dataset", f"syslog.{msg.facility_name or 'unknown'}")
    set_path(doc, "event.created", iso(msg.received_at))
    set_path(doc, "event.ingested", iso(ingested_at))
    set_path(doc, "event.original", msg.raw)
    set_path(doc, "network.transport", "udp")
    set_path(doc, "network.protocol", "syslog")

    if msg.priority is not None:
        set_path(doc, "log.syslog.priority", msg.priority)
        set_path(doc, "log.syslog.facility.code", msg.facility)
        set_path(doc, "log.syslog.facility.name", msg.facility_name)
        set_path(doc, "log.syslog.severity.code", msg.severity)
        set_path(doc, "log.syslog.severity.name", msg.severity_name)
        set_path(doc, "log.level", msg.severity_name)
    if msg.version is not None:
        set_path(doc, "log.syslog.version", str(msg.version))
    set_path(doc, "log.syslog.hostname", msg.hostname)
    set_path(doc, "log.syslog.appname", msg.app_name)
    set_path(doc, "log.syslog.procid", msg.procid)
    set_path(doc, "log.syslog.msgid", msg.msgid)
    if msg.structured_data:
        set_path(doc, "log.syslog.structured_data", msg.structured_data)

    set_path(doc, "host.hostname", msg.hostname)
    set_path(doc, "host.name", msg.hostname)
    set_path(doc, "process.name", msg.app_name)
    if msg.procid and msg.procid.isdigit():
        set_path(doc, "process.pid", int(msg.procid))
    if peer_ip:
        labels = {"syslog_peer_ip": peer_ip}
        if peer_port is not None:
            labels["syslog_peer_port"] = str(peer_port)
        doc["labels"] = labels

    tags: list[str] = []
    if msg.format == "unknown":
        tags.append("_syslog_parse_failure")
    elif msg.timestamp is None:
        tags.append("_syslog_timestamp_missing")

    classified = False
    stripped = msg.message.lstrip()
    if stripped.startswith("{"):
        classified = _apply_windows_json(doc, stripped)
    if not classified:
        for rule in MESSAGE_RULES:
            hit = rule.pattern.search(msg.message)
            if not hit:
                continue
            g = {k: v for k, v in hit.groupdict().items() if v}
            set_path(doc, "event.action", rule.action)
            set_path(doc, "event.category", list(rule.category))
            set_path(doc, "event.type", list(rule.type))
            set_path(doc, "event.outcome", rule.outcome)
            if "ip" in g and _is_ip(g["ip"]):
                set_path(doc, "source.ip", g["ip"])
            if "port" in g and 0 < int(g["port"]) < 65536:
                set_path(doc, "source.port", int(g["port"]))
            set_path(doc, "user.name", g.get("user"))
            set_path(doc, "user.effective.name", g.get("euser"))
            set_path(doc, "user.target.name", g.get("target"))
            set_path(doc, "group.name", g.get("group"))
            set_path(doc, "process.command_line", g.get("cmd", "").strip() or None)
            set_path(doc, "process.working_directory", g.get("cwd"))
            tags.extend(rule.tags)
            classified = True
            break
    if not classified:
        set_path(doc, "event.category", ["host"])
        set_path(doc, "event.type", ["info"])
        set_path(doc, "event.outcome", "unknown")

    related_ip = [ip for ip in (get_path(doc, "source.ip"),) if ip]
    related_user = sorted({u for u in (get_path(doc, "user.name"), get_path(doc, "user.target.name"),
                                       get_path(doc, "user.effective.name")) if u})
    set_path(doc, "related.ip", related_ip)
    set_path(doc, "related.user", related_user)
    set_path(doc, "related.hosts", [msg.hostname] if msg.hostname else [])
    set_path(doc, "tags", tags)

    validate(doc)
    return doc
