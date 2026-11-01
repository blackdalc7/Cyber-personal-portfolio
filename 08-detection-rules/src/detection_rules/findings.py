"""Turn a rule hit into an OCSF 1.4.0 Detection Finding [2004]."""

from __future__ import annotations

import hashlib
from typing import Any

from .rules import CompiledRule

PRODUCT = {"name": "detection-rules", "vendor_name": "Watchfloor portfolio"}
MATCH_FIELDS = ("process_path", "cmd_line", "parent_path", "target_file", "user_name", "dst_ip", "dst_port")


def finding_uid(rule_id: str, event_uid: str) -> str:
    """Deterministic: the same rule on the same event always yields the same finding uid (safe to re-run)."""
    return "rules-" + hashlib.sha256(f"{rule_id}|{event_uid}".encode()).hexdigest()[:32]


def to_finding(rule: CompiledRule, hit: dict[str, Any], *, now_ms: int) -> dict[str, Any]:
    uid = finding_uid(rule.id, str(hit["uid"]))
    attacks = []
    for tid in rule.techniques:
        item: dict[str, Any] = {"technique": {"uid": tid}, "version": "v17"}
        if rule.tactics:
            item["tactic"] = {"name": rule.tactics[0]}
        attacks.append(item)
    doc: dict[str, Any] = {
        "class_uid": 2004, "category_uid": 2, "activity_id": 1, "type_uid": 200401,
        "severity_id": rule.severity_id, "time": now_ms, "message": rule.title,
        "metadata": {"version": "1.4.0", "uid": uid, "product": dict(PRODUCT),
                     "labels": [f"rule:{rule.id}"]},
        "finding_info": {
            "uid": uid, "title": rule.title,
            "analytic": {"uid": rule.id, "name": rule.title, "type_id": 1},
            "attacks": attacks, "related_events": [{"uid": str(hit["uid"])}], "types": ["sigma"],
        },
        "unmapped": {"rule_path": rule.path, "level": rule.level, "event_time": int(hit["time"]),
                     "matched": {k: hit[k] for k in MATCH_FIELDS if hit.get(k) is not None}},
    }
    if rule.description:
        doc["finding_info"]["desc"] = rule.description
    if hit.get("hostname"):
        doc["device"] = {"hostname": str(hit["hostname"])}
    proc = {k: v for k, v in (("name", hit.get("process_name")), ("cmd_line", hit.get("cmd_line"))) if v}
    if proc:
        doc["actor"] = {"process": proc}
    return doc
