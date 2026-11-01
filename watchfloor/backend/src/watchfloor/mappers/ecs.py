"""ECS 8.11 → OCSF mappers for the documents that projects 01 (AI-SIEM) and 03 (EDR canary) emit.

Both projects keep writing ECS, so their own tests and consumers are untouched; the
spine adapters call these functions on every NDJSON line they tail.
"""

from __future__ import annotations

from typing import Any

from .. import ocsf


def _get(doc: dict[str, Any], dotted: str, default: Any = None) -> Any:
    cur: Any = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _device(doc: dict[str, Any]) -> dict[str, Any] | None:
    host = _get(doc, "host.hostname") or _get(doc, "host.name")
    if not host:
        hosts = _as_list(_get(doc, "related.hosts"))
        host = hosts[0] if hosts else None
    if not host:
        return None
    out: dict[str, Any] = {"hostname": str(host)}
    ip = _as_list(_get(doc, "host.ip"))
    if ip:
        out["ip"] = str(ip[0])
    return out


def _process(doc: dict[str, Any]) -> dict[str, Any] | None:
    proc = _get(doc, "process")
    if not isinstance(proc, dict):
        return None
    out: dict[str, Any] = {}
    if proc.get("pid") is not None:
        out["pid"] = int(proc["pid"])
    name = proc.get("name") or proc.get("executable")
    if name:
        out["name"] = str(name).replace("\\", "/").rsplit("/", 1)[-1]
        if "\\" in str(name) or "/" in str(name):
            out["file"] = ocsf.file_obj(str(name))
    if proc.get("command_line"):
        out["cmd_line"] = str(proc["command_line"])
    parent = proc.get("parent")
    if isinstance(parent, dict):
        pp: dict[str, Any] = {}
        if parent.get("pid") is not None:
            pp["pid"] = int(parent["pid"])
        if parent.get("name"):
            pp["name"] = str(parent["name"]).replace("\\", "/").rsplit("/", 1)[-1]
        if pp:
            out["parent_process"] = pp
    return out or None


def _labels(scenario: str | None) -> list[str] | None:
    return [f"scenario:{scenario}"] if scenario else None


def map_ecs_event(doc: dict[str, Any], *, product: str, scenario: str | None = None) -> dict[str, Any] | None:
    """Map one ECS *event* (``event.kind: event``) to an OCSF activity event.

    Returns ``None`` for events with no OCSF class in the Watchfloor subset (they stay in
    the project's own NDJSON).
    """
    cats = set(_as_list(_get(doc, "event.category")))
    action = _get(doc, "event.action")
    outcome = _get(doc, "event.outcome")
    ts = _get(doc, "@timestamp")
    common = {"time": ts, "product": product, "uid": _get(doc, "event.id"), "message": doc.get("message"),
              "labels": _labels(scenario)}
    device = _device(doc)
    user = _get(doc, "user.name")

    if "authentication" in cats:
        status = ocsf.STATUS_SUCCESS if outcome == "success" else ocsf.STATUS_FAILURE if outcome == "failure" else 0
        out = ocsf.new_event(ocsf.AUTHENTICATION, 1, severity_id=ocsf.SEV_INFO, **common)
        out["status_id"] = status
        out["user"] = {"name": str(user or "unknown")}
        if _get(doc, "source.ip"):
            out["src_endpoint"] = {"ip": str(_get(doc, "source.ip"))}
            if _get(doc, "source.port") is not None:
                out["src_endpoint"]["port"] = int(_get(doc, "source.port"))
        if device:
            out["device"] = device
            out["dst_endpoint"] = {"hostname": device["hostname"]}
        out["auth_protocol"] = str(_get(doc, "process.name") or action or "unknown")
        out["is_remote"] = bool(_get(doc, "source.ip"))
        return out

    if "iam" in cats and action in {"user_created", "group_member_added", "user_modified", "password_changed"}:
        activity = {"user_created": 1, "password_changed": 3, "group_member_added": 7, "user_modified": 99}[action]
        out = ocsf.new_event(ocsf.ACCOUNT_CHANGE, activity, severity_id=ocsf.SEV_LOW, **common)
        out["status_id"] = ocsf.STATUS_SUCCESS if outcome != "failure" else ocsf.STATUS_FAILURE
        target = _get(doc, "user.target.name") or user or "unknown"
        out["user"] = {"name": str(target)}
        if device:
            out["device"] = device
        proc = _process(doc)
        if proc:
            out["actor"] = {"process": proc}
        return out

    if "process" in cats and device:
        proc = _process(doc) or {"name": str(action or "unknown")}
        if user:
            proc["user"] = {"name": str(user)}
        out = ocsf.new_event(ocsf.PROCESS_ACTIVITY, 1, severity_id=ocsf.SEV_INFO, **common)
        out["process"] = proc
        out["device"] = device
        return out
    return None


def map_ecs_alert(doc: dict[str, Any], *, product: str, scenario: str | None = None,
                  correlation_uid: str | None = None) -> dict[str, Any]:
    """Map one ECS alert (``event.kind: alert``) from 01 or 03 to an OCSF Detection Finding."""
    severity = _get(doc, "event.severity")
    rule_id = _get(doc, "rule.id") or "unknown"
    rule_name = _get(doc, "rule.name") or rule_id
    chain = _get(doc, "siem.chain") or {}
    out = ocsf.new_event(
        ocsf.DETECTION_FINDING, 1, time=_get(doc, "@timestamp"), product=product,
        severity_id=ocsf.severity_from_score(severity), uid=_get(doc, "event.id"), message=doc.get("message"),
        correlation_uid=correlation_uid or chain.get("id"), labels=_labels(scenario))
    info: dict[str, Any] = {
        "uid": _get(doc, "event.id") or out["metadata"]["uid"],
        "title": str(rule_name),
        "analytic": {"uid": str(rule_id), "name": str(rule_name), "type_id": 1},
        "attacks": ocsf.attacks(
            _as_list(_get(doc, "threat.technique.id")), _as_list(_get(doc, "threat.technique.name")),
            _as_list(_get(doc, "threat.tactic.id")), _as_list(_get(doc, "threat.tactic.name"))),
        "types": ["chain"] if chain else ["alert"],
    }
    if _get(doc, "rule.description") or _get(doc, "event.reason"):
        info["desc"] = str(_get(doc, "event.reason") or _get(doc, "rule.description"))
    trigger = _as_list(_get(doc, "siem.alert.trigger_event_ids")) or _as_list(chain.get("alert_ids"))
    if trigger:
        info["related_events"] = [{"uid": str(u)} for u in trigger[:500]]
    out["finding_info"] = info
    if severity is not None:
        out["risk_score"] = max(0, min(100, round(float(severity))))
    device = _device(doc)
    if device:
        out["device"] = device
    if _get(doc, "source.ip"):
        out["src_endpoint"] = {"ip": str(_get(doc, "source.ip"))}
    proc = _process(doc)
    user = _get(doc, "user.name")
    if proc or user:
        out["actor"] = {}
        if proc:
            out["actor"]["process"] = proc
        if user:
            out["actor"]["user"] = {"name": str(user)}
    unmapped: dict[str, Any] = {}
    for key in ("file.path", "edr.ancestry", "edr.markers", "edr.distinct_files", "event.dataset"):
        val = _get(doc, key)
        if val is not None:
            unmapped[key] = val
    if chain:
        unmapped["chain"] = {k: chain[k] for k in ("attack_stage", "verdict", "summary", "recommended_actions",
                                                    "alert_count", "rule_ids") if k in chain}
    if unmapped:
        out["unmapped"] = unmapped
    return out


def map_ecs(doc: dict[str, Any], *, product: str, scenario: str | None = None) -> dict[str, Any] | None:
    """Dispatch an ECS document to the event or alert mapper by ``event.kind``."""
    if _get(doc, "event.kind") == "alert":
        return map_ecs_alert(doc, product=product, scenario=scenario)
    return map_ecs_event(doc, product=product, scenario=scenario)
