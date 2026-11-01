"""Every query the hub (and the replay exporter) runs against the lake.

All SQL is fixed text with ``?`` parameters; nothing a client sends is ever pasted
into a statement. Each function returns plain JSON-safe structures, so the same code
produces the live API responses and the static files of the GitHub Pages demo.
"""

from __future__ import annotations

import json
from typing import Any

from .. import ocsf
from ..lake import LakeReader

DEFAULT_LIMIT = 200
MAX_LIMIT = 2000

_LIST_COLS = ("time, class_uid, activity_id, severity_id, status_id, uid, correlation_uid, product, hostname, "
              "src_ip, user_name, process_name, process_pid, parent_pid, cmd_line, file_path, finding_uid, "
              "finding_title, techniques, scenario, message")


def _limit(n: int | None) -> int:
    return max(1, min(int(n or DEFAULT_LIMIT), MAX_LIMIT))


def _where(filters: dict[str, Any]) -> tuple[str, list[Any]]:
    clauses, params = ["1=1"], []
    if filters.get("class_uid") is not None:
        clauses.append("class_uid = ?")
        params.append(int(filters["class_uid"]))
    if filters.get("classes"):
        clauses.append(f"class_uid IN ({', '.join('?' for _ in filters['classes'])})")
        params.extend(int(c) for c in filters["classes"])
    for col in ("hostname", "product", "scenario", "correlation_uid", "src_ip", "user_name"):
        if filters.get(col):
            clauses.append(f"{col} = ?")
            params.append(str(filters[col]))
    if filters.get("since") is not None:
        clauses.append("time >= ?")
        params.append(int(filters["since"]))
    if filters.get("until") is not None:
        clauses.append("time <= ?")
        params.append(int(filters["until"]))
    if filters.get("min_severity") is not None:
        clauses.append("severity_id >= ?")
        params.append(int(filters["min_severity"]))
    if filters.get("technique"):
        clauses.append("EXISTS (SELECT 1 FROM unnest(techniques) AS u(t) WHERE u.t = ? OR split_part(u.t, '.', 1) = ?)")
        params += [str(filters["technique"]).upper(), str(filters["technique"]).upper()]
    if filters.get("q"):
        clauses.append("(contains(lower(coalesce(message, '')), ?) OR contains(lower(coalesce(cmd_line, '')), ?) "
                       "OR contains(lower(coalesce(finding_title, '')), ?))")
        q = str(filters["q"]).lower()[:200]
        params += [q, q, q]
    return " AND ".join(clauses), params


def events(lake: LakeReader, limit: int | None = None, offset: int = 0, **filters: Any) -> list[dict[str, Any]]:
    """Activity and finding rows, newest first, filtered by any of the ``_where`` keys."""
    where, params = _where(filters)
    sql = (f"SELECT {_LIST_COLS} FROM events WHERE {where} "  # noqa: S608 - fixed clauses, values are parameters
           "ORDER BY time DESC LIMIT ? OFFSET ?")
    return lake.query(sql, [*params, _limit(limit), max(0, int(offset))])


def event_raw(lake: LakeReader, uid: str) -> dict[str, Any] | None:
    """The full OCSF document for one event uid."""
    raw = lake.scalar("SELECT raw FROM events WHERE uid = ? LIMIT 1", [uid])
    return json.loads(raw) if raw else None


def findings(lake: LakeReader, limit: int | None = None, **filters: Any) -> list[dict[str, Any]]:
    """Detection Findings, newest first."""
    return events(lake, limit=limit, class_uid=ocsf.DETECTION_FINDING, **filters)


def incidents(lake: LakeReader, **filters: Any) -> list[dict[str, Any]]:
    """The latest state of each incident (Incident Finding rows grouped by correlation uid)."""
    where, params = _where({**filters, "class_uid": ocsf.INCIDENT_FINDING})
    rows = lake.query(
        f"SELECT raw FROM events WHERE {where} "  # noqa: S608
        "QUALIFY row_number() OVER (PARTITION BY correlation_uid ORDER BY time DESC, activity_id DESC) = 1 "
        "ORDER BY time DESC", params)
    return [_incident_view(json.loads(r["raw"])) for r in rows]


def _incident_view(doc: dict[str, Any]) -> dict[str, Any]:
    un = doc.get("unmapped") or {}
    timing = un.get("timing") or {}
    detected = timing.get("detected_at")
    ack = timing.get("decided_at")
    resolved = timing.get("resolved_at")
    return {
        "id": doc["metadata"].get("correlation_uid"),
        "title": doc.get("message") or doc["finding_info_list"][0]["title"],
        "status": un.get("soar_status"),
        "status_id": doc.get("status_id"),
        "severity_id": doc.get("severity_id"),
        "host": (doc.get("device") or {}).get("hostname"),
        "indicator_ip": (doc.get("src_endpoint") or {}).get("ip"),
        "decided_by": (doc.get("assignee") or {}).get("name"),
        "description": doc.get("desc"),
        "risk_score": un.get("risk_score"),
        "time": doc["time"],
        "timing": timing,
        "tta_s": round(ack - detected, 1) if ack and detected else None,
        "ttr_s": round(resolved - detected, 1) if resolved and detected else None,
        "scenario": next((lab.split(":", 1)[1] for lab in doc["metadata"].get("labels", [])
                          if lab.startswith("scenario:")), None),
    }


def process_tree(lake: LakeReader, hostname: str, since: int | None = None, until: int | None = None
                 ) -> dict[str, Any]:
    """Nodes and edges of the process tree on ``hostname`` from Process Activity launches.

    Nodes flagged ``alert`` appear in a Detection Finding on the same host (by pid).
    """
    where, params = _where({"hostname": hostname, "class_uid": ocsf.PROCESS_ACTIVITY, "since": since, "until": until})
    rows = lake.query(
        f"SELECT time, process_pid, parent_pid, process_name, cmd_line, product FROM events "  # noqa: S608
        f"WHERE {where} AND activity_id = 1 ORDER BY time LIMIT 2000", params)
    fwhere, fparams = _where({"hostname": hostname, "class_uid": ocsf.DETECTION_FINDING, "since": since,
                              "until": until})
    flagged: dict[int, list[str]] = {}
    for f in lake.query(f"SELECT raw FROM events WHERE {fwhere}", fparams):  # noqa: S608
        doc = json.loads(f["raw"])
        pid = ((doc.get("actor") or {}).get("process") or {}).get("pid")
        if pid is not None:
            flagged.setdefault(int(pid), []).append(doc["finding_info"]["title"])
    nodes, edges, pids = [], [], set()
    for r in rows:
        pid = r["process_pid"]
        if pid is None or pid in pids:
            continue
        pids.add(pid)
        nodes.append({"id": str(pid), "pid": pid, "name": r["process_name"], "cmd_line": r["cmd_line"],
                      "time": r["time"], "alerts": flagged.get(pid, [])})
    for r in rows:
        if r["parent_pid"] is not None and r["process_pid"] is not None and r["parent_pid"] in pids:
            edges.append({"source": str(r["parent_pid"]), "target": str(r["process_pid"])})
    return {"host": hostname, "nodes": nodes, "edges": edges}


def incident_detail(lake: LakeReader, incident_id: str, pad_ms: int = 30 * 60 * 1000) -> dict[str, Any] | None:
    """One incident with its state history, related findings, process tree and timeline."""
    history = lake.query("SELECT raw FROM events WHERE class_uid = ? AND correlation_uid = ? ORDER BY time",
                         [ocsf.INCIDENT_FINDING, incident_id])
    if not history:
        return None
    states = [_incident_view(json.loads(h["raw"])) for h in history]
    latest = states[-1]
    timing = latest["timing"]
    start = int(min(timing.get("detected_at") or latest["time"] / 1000, latest["time"] / 1000) * 1000) - pad_ms
    end = int(max(timing.get("resolved_at") or 0, latest["time"] / 1000) * 1000) + pad_ms // 6
    host = latest["host"]
    related = findings(lake, limit=500, hostname=host, since=start, until=end) if host else []
    activity = events(lake, limit=500, hostname=host, since=start, until=end,
                      classes=[ocsf.PROCESS_ACTIVITY, ocsf.FILE_ACTIVITY, ocsf.ACCOUNT_CHANGE, ocsf.NETWORK_ACTIVITY]
                      ) if host else []
    auth = lake.query(
        "SELECT status_id, src_ip, user_name, count(*) AS n, min(time) AS first, max(time) AS last FROM events "
        "WHERE class_uid = ? AND hostname = ? AND time BETWEEN ? AND ? GROUP BY ALL ORDER BY first",
        [ocsf.AUTHENTICATION, host, start, end]) if host else []
    chain = next((json.loads(r["raw"]).get("unmapped", {}).get("chain") for r in lake.query(
        "SELECT raw FROM events WHERE class_uid = ? AND hostname = ? AND time BETWEEN ? AND ? "
        "AND json_contains(raw::JSON->'$.finding_info.types', '\"chain\"') ORDER BY time DESC LIMIT 1",
        [ocsf.DETECTION_FINDING, host, start, end])), None) if host else None
    timeline = sorted(
        [{"time": f["time"], "kind": "finding", "title": f["finding_title"], "product": f["product"],
          "severity_id": f["severity_id"], "uid": f["uid"]} for f in related]
        + [{"time": a["time"], "kind": "activity", "title": a["message"] or a["cmd_line"] or a["file_path"],
            "product": a["product"], "class_uid": a["class_uid"], "uid": a["uid"]} for a in activity]
        + [{"time": s["time"], "kind": "response", "title": f"Incident {s['status']}", "product": "soar-bot",
            "actor": s["decided_by"]} for s in states],
        key=lambda x: x["time"])
    return {"incident": latest, "history": states, "findings": related, "auth_summary": auth, "chain": chain,
            "process_tree": process_tree(lake, host, start, end) if host else None, "timeline": timeline[-400:]}


def summary(lake: LakeReader, since: int | None = None, scenario: str | None = None) -> dict[str, Any]:
    """KPI tiles, the noise funnel, severity mix and an event histogram for the Watch floor."""
    where, params = _where({"since": since, "scenario": scenario})
    by_class = {r["class_uid"]: r["n"] for r in lake.query(
        f"SELECT class_uid, count(*) AS n FROM events WHERE {where} GROUP BY 1", params)}  # noqa: S608
    by_product = lake.query(
        f"SELECT product, count(*) AS n FROM events WHERE {where} AND class_uid = ? GROUP BY 1 ORDER BY 2 DESC",  # noqa: S608
        [*params, ocsf.DETECTION_FINDING])
    sev = {r["severity_id"]: r["n"] for r in lake.query(
        f"SELECT severity_id, count(*) AS n FROM events WHERE {where} AND class_uid = ? GROUP BY 1",  # noqa: S608
        [*params, ocsf.DETECTION_FINDING])}
    top_tech = lake.query(
        f"SELECT t AS technique, count(*) AS n FROM (SELECT unnest(techniques) AS t FROM events "  # noqa: S608
        f"WHERE {where} AND class_uid = ?) GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 10", [*params, ocsf.DETECTION_FINDING])
    hist = lake.query(
        f"SELECT (time // 60000) * 60000 AS bucket, "  # noqa: S608
        "count(*) FILTER (WHERE class_uid NOT IN (2004, 2005)) AS events, "
        "count(*) FILTER (WHERE class_uid = 2004) AS findings FROM events "
        f"WHERE {where} GROUP BY 1 ORDER BY 1", params)
    incs = incidents(lake, since=since, scenario=scenario)
    tta = [i["tta_s"] for i in incs if i["tta_s"] is not None]
    ttr = [i["ttr_s"] for i in incs if i["ttr_s"] is not None]
    activity_total = sum(n for c, n in by_class.items() if c not in ocsf.FINDING_CLASSES)
    detector_findings = sum(r["n"] for r in by_product if r["product"] not in ("alert-triage",))
    triage = lake.query(
        "SELECT count(*) FILTER (WHERE NOT json_contains(raw::JSON->'$.finding_info.types', '\"suppress\"')) "  # noqa: S608
        "AS queued, "
        "count(*) AS total FROM events "
        f"WHERE {where} AND class_uid = ? AND product = 'alert-triage'", [*params, ocsf.DETECTION_FINDING])[0]
    return {
        "events_by_class": {ocsf.CLASSES[c][2] if c in ocsf.CLASSES else str(c): n
                            for c, n in sorted(by_class.items())},
        "findings_by_product": by_product,
        "findings_by_severity": {ocsf.SEVERITY_NAMES.get(k, str(k)): v for k, v in sorted(sev.items())},
        "top_techniques": top_tech,
        "histogram": hist,
        "funnel": [step for step in [
            {"stage": "Activity events", "count": activity_total},
            {"stage": "Detector findings", "count": detector_findings},
            {"stage": "Triage queue", "count": triage["queued"]} if triage["total"] else None,
            {"stage": "Incidents", "count": len(incs)},
            {"stage": "Contained", "count": sum(1 for i in incs if i["status"] == "remediated")},
        ] if step],
        "kpis": {
            "open_incidents": sum(1 for i in incs if i["status"] not in ("remediated", "rejected", "closed")),
            "incidents": len(incs),
            "mtta_s": round(sum(tta) / len(tta), 1) if tta else None,
            "mttr_s": round(sum(ttr) / len(ttr), 1) if ttr else None,
            "findings": by_class.get(ocsf.DETECTION_FINDING, 0),
            "events": activity_total,
        },
    }


def scenario_events(lake: LakeReader, scenario: str) -> list[dict[str, Any]]:
    """Full OCSF documents labelled with ``scenario`` (for live scoring)."""
    return [json.loads(r["raw"]) for r in lake.query(
        "SELECT raw FROM events WHERE scenario = ? ORDER BY time LIMIT 50000", [scenario])]
