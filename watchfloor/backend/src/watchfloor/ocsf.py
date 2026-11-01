"""The Watchfloor event contract: a documented subset of OCSF 1.4.0.

Every event on the spine is an OCSF object of one of seven classes. Projects keep their
own internal schema (ECS for 01, 03 and 06); the mappers in :mod:`watchfloor.mappers`
translate at the edge, and :func:`validate` enforces the contract with JSON Schema
before anything reaches Redis or the Parquet lake.

Fields that OCSF has no attribute for go under ``unmapped``, which is OCSF's own
convention, so nothing is silently dropped.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from functools import cache
from importlib import resources
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

OCSF_VERSION = "1.4.0"

FILE_ACTIVITY = 1001
PROCESS_ACTIVITY = 1007
DETECTION_FINDING = 2004
INCIDENT_FINDING = 2005
ACCOUNT_CHANGE = 3001
AUTHENTICATION = 3002
NETWORK_ACTIVITY = 4001

CLASSES: dict[int, tuple[str, int, str]] = {
    FILE_ACTIVITY: ("file_activity", 1, "File System Activity"),
    PROCESS_ACTIVITY: ("process_activity", 1, "Process Activity"),
    DETECTION_FINDING: ("detection_finding", 2, "Detection Finding"),
    INCIDENT_FINDING: ("incident_finding", 2, "Incident Finding"),
    ACCOUNT_CHANGE: ("account_change", 3, "Account Change"),
    AUTHENTICATION: ("authentication", 3, "Authentication"),
    NETWORK_ACTIVITY: ("network_activity", 4, "Network Activity"),
}
FINDING_CLASSES = frozenset({DETECTION_FINDING, INCIDENT_FINDING})

# severity_id
SEV_UNKNOWN, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL = 0, 1, 2, 3, 4, 5
SEVERITY_NAMES = {0: "unknown", 1: "informational", 2: "low", 3: "medium", 4: "high", 5: "critical", 6: "fatal"}

# status_id for activity classes
STATUS_SUCCESS, STATUS_FAILURE = 1, 2

# Incident Finding status_id
INC_NEW, INC_IN_PROGRESS, INC_ON_HOLD, INC_RESOLVED, INC_CLOSED = 1, 2, 3, 4, 5


class ContractError(ValueError):
    """Raised when a document does not satisfy the Watchfloor OCSF contract."""


def severity_from_score(score: float | int | None) -> int:
    """Map a 0-100 risk score (ECS ``event.severity``) to an OCSF ``severity_id``."""
    if score is None:
        return SEV_UNKNOWN
    s = float(score)
    if s >= 90:
        return SEV_CRITICAL
    if s >= 70:
        return SEV_HIGH
    if s >= 40:
        return SEV_MEDIUM
    if s >= 20:
        return SEV_LOW
    return SEV_INFO


def severity_from_label(label: str | None) -> int:
    """Map a severity word (low/medium/high/critical/...) to an OCSF ``severity_id``."""
    table = {"informational": 1, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    return table.get((label or "").strip().lower(), SEV_UNKNOWN)


def to_epoch_ms(value: str | datetime | int | float | None) -> int:
    """Convert an ISO-8601 string, datetime or epoch (s or ms) to epoch milliseconds UTC."""
    if value is None:
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    if isinstance(value, (int, float)):
        # Anything below 10^11 is seconds (that is the year 5138 in ms).
        return int(value * 1000) if value < 1e11 else int(value)
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    text = str(value).strip().replace("Z", "+00:00")
    # Python < 3.11 accepts at most 6 fractional digits.
    if "." in text:
        head, _, tail = text.partition(".")
        digits = "".join(ch for ch in tail if ch.isdigit())
        rest = tail[len(digits):]
        text = f"{head}.{digits[:6]}{rest}"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def iso(ms: int) -> str:
    """Render epoch milliseconds as an ISO-8601 UTC string with a ``Z`` suffix."""
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_event(class_uid: int, activity_id: int, *, time: Any, product: str, severity_id: int = SEV_INFO,
              uid: str | None = None, message: str | None = None, correlation_uid: str | None = None,
              labels: list[str] | None = None, vendor: str = "Watchfloor portfolio") -> dict[str, Any]:
    """Create the common OCSF envelope for ``class_uid``; callers add class-specific attributes."""
    if class_uid not in CLASSES:
        raise ContractError(f"class_uid {class_uid} is not part of the Watchfloor contract")
    meta: dict[str, Any] = {
        "version": OCSF_VERSION,
        "uid": uid or str(uuid.uuid4()),
        "product": {"name": product, "vendor_name": vendor},
    }
    if correlation_uid:
        meta["correlation_uid"] = correlation_uid
    if labels:
        meta["labels"] = list(labels)
    doc: dict[str, Any] = {
        "class_uid": class_uid,
        "category_uid": CLASSES[class_uid][1],
        "activity_id": activity_id,
        "type_uid": class_uid * 100 + activity_id,
        "severity_id": severity_id,
        "time": to_epoch_ms(time),
        "metadata": meta,
    }
    if message:
        doc["message"] = message[:8192]
    return doc


def attacks(technique_ids: list[str] | tuple[str, ...] | None, technique_names: list[str] | None = None,
            tactic_ids: list[str] | None = None, tactic_names: list[str] | None = None) -> list[dict[str, Any]]:
    """Build an OCSF ``attacks`` array from parallel lists of ATT&CK ids and names."""
    out = []
    names = list(technique_names or [])
    t_ids, t_names = list(tactic_ids or []), list(tactic_names or [])
    for i, tid in enumerate(technique_ids or []):
        item: dict[str, Any] = {"technique": {"uid": tid}, "version": "v17"}
        if i < len(names) and names[i]:
            item["technique"]["name"] = names[i]
        if t_ids:
            tac = {"uid": t_ids[min(i, len(t_ids) - 1)]}
            if t_names:
                tac["name"] = t_names[min(i, len(t_names) - 1)]
            item["tactic"] = tac
        out.append(item)
    return out


def file_obj(path: str) -> dict[str, Any]:
    """Build an OCSF ``file`` object from a Windows or POSIX path."""
    name = path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or path
    return {"name": name, "path": path}


@cache
def _validators() -> dict[int, Draft202012Validator]:
    pkg = resources.files("watchfloor.schemas")
    base = json.loads(pkg.joinpath("base_event.schema.json").read_text(encoding="utf-8"))
    registry = Registry().with_resource("base_event.schema.json", Resource.from_contents(base))
    out = {}
    for class_uid, (name, _, _) in CLASSES.items():
        schema = json.loads(pkg.joinpath(f"{name}.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        out[class_uid] = Draft202012Validator(schema, registry=registry)
    return out


def validate(doc: dict[str, Any]) -> dict[str, Any]:
    """Validate ``doc`` against its class schema and the type_uid rule; return it unchanged.

    Raises:
        ContractError: with the first few schema violations, if any.
    """
    class_uid = doc.get("class_uid")
    validator = _validators().get(class_uid) if isinstance(class_uid, int) else None
    if validator is None:
        raise ContractError(f"unsupported class_uid: {class_uid!r}")
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
    if errors:
        detail = "; ".join(f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}" for e in errors[:5])
        raise ContractError(detail)
    if doc["type_uid"] != class_uid * 100 + doc["activity_id"]:
        raise ContractError("type_uid must equal class_uid * 100 + activity_id")
    return doc


def techniques_of(doc: dict[str, Any]) -> list[str]:
    """Return the ATT&CK technique ids carried by a finding (empty for activity events)."""
    info = doc.get("finding_info") or {}
    out = [a["technique"]["uid"] for a in info.get("attacks", []) if a.get("technique", {}).get("uid")]
    return sorted(set(out))


def flatten(doc: dict[str, Any]) -> dict[str, Any]:
    """Project an OCSF event onto the flat column set stored in the Parquet lake.

    The full document is kept in ``raw`` so nothing is lost; the other columns exist
    so that hunts and dashboards can filter without parsing JSON.
    """
    meta = doc.get("metadata", {})
    device = doc.get("device") or {}
    proc = doc.get("process") or (doc.get("actor") or {}).get("process") or {}
    user = doc.get("user") or (doc.get("actor") or {}).get("user") or proc.get("user") or {}
    file_ = doc.get("file") or proc.get("file") or {}
    info = doc.get("finding_info") or {}
    if doc.get("class_uid") == INCIDENT_FINDING and doc.get("finding_info_list"):
        info = {"uid": meta.get("correlation_uid") or meta.get("uid"), "title": doc["finding_info_list"][0]["title"]}
    labels = meta.get("labels") or []
    scenario = next((lab.split(":", 1)[1] for lab in labels if lab.startswith("scenario:")), None)
    return {
        "time": int(doc["time"]),
        "class_uid": int(doc["class_uid"]),
        "category_uid": int(doc["category_uid"]),
        "activity_id": int(doc["activity_id"]),
        "type_uid": int(doc["type_uid"]),
        "severity_id": int(doc.get("severity_id", 0)),
        "status_id": doc.get("status_id"),
        "uid": meta.get("uid"),
        "correlation_uid": meta.get("correlation_uid"),
        "product": (meta.get("product") or {}).get("name"),
        "hostname": device.get("hostname") or (doc.get("dst_endpoint") or {}).get("hostname"),
        "src_ip": (doc.get("src_endpoint") or {}).get("ip"),
        "user_name": user.get("name"),
        "process_name": proc.get("name"),
        "process_pid": proc.get("pid"),
        "parent_pid": (proc.get("parent_process") or {}).get("pid"),
        "cmd_line": proc.get("cmd_line"),
        "file_path": file_.get("path"),
        "finding_uid": info.get("uid"),
        "finding_title": info.get("title"),
        "techniques": techniques_of(doc),
        "scenario": scenario,
        "message": doc.get("message"),
        "raw": json.dumps(doc, separators=(",", ":"), ensure_ascii=False, sort_keys=True),
    }
