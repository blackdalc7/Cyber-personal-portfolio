"""Mappers for the non-ECS sources: 03 raw ETW records, 06 meta-alerts, 02 incidents,
Tetragon (eBPF) export lines and Windows event log records shipped by Fluent Bit."""

from __future__ import annotations

import re
from typing import Any

from .. import ocsf

# --------------------------------------------------------------------------- 03 raw ETW records

_EDR_FILE_ACTIVITY = {"FileCreate": 1, "FileRead": 2, "FileWrite": 3, "DiskWrite": 3, "FileDelete": 4,
                      "FileRename": 5}


def map_edr_record(rec: dict[str, Any], *, host: str, scenario: str | None = None) -> dict[str, Any] | None:
    """Map one 03 ETW record (``ProcessStart``, ``FileWrite``...) to OCSF; ``None`` if unusable."""
    kind = rec.get("Type")
    ts = rec.get("TimeStamp")
    pid = rec.get("ProcessId")
    if not ts or not isinstance(pid, int):
        return None
    labels = [f"scenario:{scenario}"] if scenario else None
    device = {"hostname": host}
    if kind in ("ProcessStart", "ProcessStop"):
        image = str(rec.get("ImageName") or "")
        proc: dict[str, Any] = {"pid": pid, "name": image.replace("\\", "/").rsplit("/", 1)[-1] or "unknown"}
        if "\\" in image or "/" in image:
            proc["file"] = ocsf.file_obj(image)
        if rec.get("CommandLine"):
            proc["cmd_line"] = str(rec["CommandLine"])
        if isinstance(rec.get("ParentProcessId"), int):
            proc["parent_process"] = {"pid": rec["ParentProcessId"]}
        out = ocsf.new_event(ocsf.PROCESS_ACTIVITY, 1 if kind == "ProcessStart" else 2, time=ts,
                             product="edr-canary", labels=labels)
        out["process"] = proc
        out["device"] = device
        return out
    if kind in _EDR_FILE_ACTIVITY and rec.get("FilePath"):
        out = ocsf.new_event(ocsf.FILE_ACTIVITY, _EDR_FILE_ACTIVITY[kind], time=ts, product="edr-canary",
                             labels=labels)
        out["file"] = ocsf.file_obj(str(rec["FilePath"]))
        if isinstance(rec.get("Size"), int):
            out["file"]["size"] = rec["Size"]
        out["actor"] = {"process": {"pid": pid}}
        out["device"] = device
        return out
    return None


# --------------------------------------------------------------------------- 06 meta-alerts

def map_meta_alert(item: dict[str, Any], *, run_time: Any, scenario: str | None = None) -> dict[str, Any]:
    """Map one 06 queue or suppressed meta-alert to a Detection Finding from ``alert-triage``."""
    disposition = item.get("disposition", "investigate")
    sev = ocsf.severity_from_label(item.get("severity"))
    if disposition == "suppress":
        sev = ocsf.SEV_INFO
    out = ocsf.new_event(ocsf.DETECTION_FINDING, 1, time=item.get("last_seen") or run_time, product="alert-triage",
                         severity_id=sev, uid=f"triage-{item['id']}", message=item.get("signature"),
                         labels=[f"scenario:{scenario}"] if scenario else None)
    out["finding_info"] = {
        "uid": str(item["id"]),
        "title": ", ".join(item.get("rules", [])[:3]) or str(item["id"]),
        "analytic": {"uid": "triage-dbscan", "name": "DBSCAN meta-alert clustering", "type_id": 3},
        "types": ["meta-alert", disposition],
        "attacks": ocsf.attacks(item.get("techniques") or []),
    }
    if item.get("targets"):
        out["device"] = {"hostname": str(item["targets"][0])}
    if item.get("sources"):
        out["src_endpoint"] = {"ip": str(item["sources"][0])}
    out["unmapped"] = {k: item[k] for k in ("count", "disposition", "reason", "category", "cohesion",
                                            "first_seen", "evidence") if k in item}
    return out


# --------------------------------------------------------------------------- 02 incidents

_SOAR_STATUS = {"new": ocsf.INC_NEW, "awaiting_approval": ocsf.INC_ON_HOLD, "approved": ocsf.INC_IN_PROGRESS,
                "remediating": ocsf.INC_IN_PROGRESS, "remediated": ocsf.INC_RESOLVED, "failed": ocsf.INC_IN_PROGRESS,
                "rejected": ocsf.INC_CLOSED, "expired": ocsf.INC_ON_HOLD, "closed": ocsf.INC_CLOSED}
_SOAR_PRIORITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def map_incident(inc: dict[str, Any], *, scenario: str | None = None) -> dict[str, Any]:
    """Map a 02 incident (``GET /incidents`` row) to an OCSF Incident Finding.

    The activity is ``Create`` for a new incident, ``Close`` once it is terminal and
    ``Update`` otherwise; the latest row per incident wins in the lake.
    """
    status = str(inc.get("status", "new"))
    terminal = status in {"remediated", "rejected", "closed"}
    activity = 3 if terminal else (1 if status == "new" else 2)
    changed = max(float(inc.get(k) or 0) for k in ("detected_at", "approval_requested_at", "decided_at",
                                                     "remediation_started_at", "resolved_at"))
    out = ocsf.new_event(ocsf.INCIDENT_FINDING, activity, time=changed or inc.get("detected_at"), product="soar-bot",
                         severity_id=ocsf.severity_from_label(inc.get("severity")),
                         uid=f"{inc['id']}:{status}", message=inc.get("title"), correlation_uid=str(inc["id"]),
                         labels=[f"scenario:{scenario}"] if scenario else None)
    out["finding_info_list"] = [{"uid": str(inc.get("external_id") or inc["id"]), "title": str(inc.get("title"))}]
    out["status_id"] = _SOAR_STATUS.get(status, 99)
    out["priority_id"] = _SOAR_PRIORITY.get(str(inc.get("severity")), 0)
    if inc.get("description"):
        out["desc"] = str(inc["description"])
    if inc.get("decided_by"):
        out["assignee"] = {"name": str(inc["decided_by"])}
    if inc.get("host"):
        out["device"] = {"hostname": str(inc["host"])}
    if inc.get("indicator_ip"):
        out["src_endpoint"] = {"ip": str(inc["indicator_ip"])}
    timing = {k: inc.get(k) for k in ("detected_at", "created_at", "approval_requested_at", "decided_at",
                                       "remediation_started_at", "resolved_at") if inc.get(k)}
    out["unmapped"] = {"soar_status": status, "risk_score": inc.get("risk_score"), "timing": timing,
                       "source": inc.get("source"), "remediation_output": inc.get("remediation_output")}
    return out


# --------------------------------------------------------------------------- Tetragon (eBPF)

def _tg_process(p: dict[str, Any]) -> dict[str, Any]:
    binary = str(p.get("binary") or "")
    out: dict[str, Any] = {"name": binary.rsplit("/", 1)[-1] or "unknown"}
    if binary:
        out["file"] = ocsf.file_obj(binary)
    if isinstance(p.get("pid"), int):
        out["pid"] = p["pid"]
    if p.get("exec_id"):
        out["uid"] = str(p["exec_id"])
    args = p.get("arguments")
    out["cmd_line"] = f"{binary} {args}".strip() if args else binary
    if p.get("uid") is not None:
        out["user"] = {"uid": str(p["uid"]), "name": "root" if p["uid"] == 0 else str(p["uid"])}
    return out


def map_tetragon(line: dict[str, Any], *, scenario: str | None = None) -> dict[str, Any] | None:
    """Map one Tetragon JSON export line (``process_exec``, ``process_exit``, ``process_kprobe``)."""
    labels = [f"scenario:{scenario}"] if scenario else None
    node = line.get("node_name") or "k8s-node"
    ts = line.get("time")
    for kind in ("process_exec", "process_exit", "process_kprobe"):
        body = line.get(kind)
        if isinstance(body, dict):
            break
    else:
        return None
    proc = _tg_process(body.get("process") or {})
    parent = body.get("parent") or {}
    if parent:
        pp = _tg_process(parent)
        proc["parent_process"] = {k: pp[k] for k in ("pid", "name", "cmd_line", "file") if k in pp}
    pod = (body.get("process") or {}).get("pod") or {}
    unmapped = {}
    if pod:
        unmapped["k8s"] = {"namespace": pod.get("namespace"), "pod": pod.get("name"),
                           "container": (pod.get("container") or {}).get("name"),
                           "image": ((pod.get("container") or {}).get("image") or {}).get("name")}
    device = {"hostname": str(node)}

    if kind in ("process_exec", "process_exit"):
        out = ocsf.new_event(ocsf.PROCESS_ACTIVITY, 1 if kind == "process_exec" else 2, time=ts, product="tetragon",
                             labels=labels)
        out["process"] = proc
        out["device"] = device
    else:
        func = str(body.get("function_name") or "")
        args = body.get("args") or []
        path = next((a.get("file_arg", {}).get("path") for a in args if isinstance(a, dict) and a.get("file_arg")),
                    None)
        sock = next((a.get("sock_arg") for a in args if isinstance(a, dict) and a.get("sock_arg")), None)
        if path:
            write = "write" in func or any(isinstance(a, dict) and a.get("int_arg") == 2 for a in args)
            out = ocsf.new_event(ocsf.FILE_ACTIVITY, 3 if write else 2, time=ts, product="tetragon", labels=labels)
            out["file"] = ocsf.file_obj(str(path))
        elif sock:
            out = ocsf.new_event(ocsf.NETWORK_ACTIVITY, 1, time=ts, product="tetragon", labels=labels)
            out["src_endpoint"] = {"ip": str(sock.get("saddr", "")), "port": int(sock.get("sport", 0))}
            out["dst_endpoint"] = {"ip": str(sock.get("daddr", "")), "port": int(sock.get("dport", 0))}
            out["connection_info"] = {"protocol_name": str(sock.get("protocol", "tcp")).lower(),
                                      "direction": "outbound"}
        else:
            out = ocsf.new_event(ocsf.PROCESS_ACTIVITY, 99, time=ts, product="tetragon", labels=labels)
            out["process"] = proc
        out["device"] = device
        out.setdefault("actor", {})["process"] = proc
        unmapped["kprobe"] = {"function": func, "policy": body.get("policy_name"), "action": body.get("action")}
    if unmapped:
        out["unmapped"] = unmapped
    return out


# --------------------------------------------------------------------------- Windows event log (Fluent Bit)

_KV = re.compile(r"^\s*([A-Za-z][A-Za-z ]{1,40}):\s*(.*)$")


def _message_fields(message: str) -> dict[str, str]:
    """Parse Sysmon-style ``Key: Value`` lines from a rendered event message."""
    out: dict[str, str] = {}
    for line in (message or "").splitlines():
        m = _KV.match(line)
        if m and m.group(1) not in out:
            out[m.group(1).strip()] = m.group(2).strip()
    return out


def map_winlog(rec: dict[str, Any], *, scenario: str | None = None) -> dict[str, Any] | None:
    """Map one Fluent Bit ``winevtlog`` record (Sysmon 1/3/11, Security 4624/4625) to OCSF."""
    labels = [f"scenario:{scenario}"] if scenario else None
    channel = str(rec.get("Channel") or "")
    eid = int(rec.get("EventID") or 0)
    host = str(rec.get("Computer") or "windows")
    ts = rec.get("TimeCreated")
    if isinstance(ts, str) and " " in ts and "T" not in ts:
        ts = ts.replace(" ", "T", 1)
    f = _message_fields(str(rec.get("Message") or ""))
    device = {"hostname": host}
    if channel.endswith("Sysmon/Operational"):
        if eid == 1:
            image = f.get("Image", "")
            proc: dict[str, Any] = {"name": image.replace("\\", "/").rsplit("/", 1)[-1] or "unknown",
                                    "file": ocsf.file_obj(image or "unknown"), "cmd_line": f.get("CommandLine", "")}
            if f.get("ProcessId", "").isdigit():
                proc["pid"] = int(f["ProcessId"])
            if f.get("User"):
                proc["user"] = {"name": f["User"]}
            parent: dict[str, Any] = {}
            if f.get("ParentProcessId", "").isdigit():
                parent["pid"] = int(f["ParentProcessId"])
            if f.get("ParentImage"):
                parent["name"] = f["ParentImage"].replace("\\", "/").rsplit("/", 1)[-1]
                parent["file"] = ocsf.file_obj(f["ParentImage"])
            if f.get("ParentCommandLine"):
                parent["cmd_line"] = f["ParentCommandLine"]
            if parent:
                proc["parent_process"] = parent
            out = ocsf.new_event(ocsf.PROCESS_ACTIVITY, 1, time=ts, product="sysmon", labels=labels,
                                 uid=f"{host}-sysmon-{rec.get('EventRecordID')}")
            out["process"] = proc
            out["device"] = device
            return out
        if eid == 11 and f.get("TargetFilename"):
            out = ocsf.new_event(ocsf.FILE_ACTIVITY, 1, time=ts, product="sysmon", labels=labels,
                                 uid=f"{host}-sysmon-{rec.get('EventRecordID')}")
            out["file"] = ocsf.file_obj(f["TargetFilename"])
            image = f.get("Image", "")
            out["actor"] = {"process": {"name": image.replace("\\", "/").rsplit("/", 1)[-1] or "unknown",
                                        **({"pid": int(f["ProcessId"])} if f.get("ProcessId", "").isdigit() else {})}}
            out["device"] = device
            return out
        if eid == 3 and f.get("DestinationIp"):
            out = ocsf.new_event(ocsf.NETWORK_ACTIVITY, 1, time=ts, product="sysmon", labels=labels,
                                 uid=f"{host}-sysmon-{rec.get('EventRecordID')}")
            out["src_endpoint"] = {"ip": f.get("SourceIp", ""), "port": int(f.get("SourcePort", "0") or 0)}
            out["dst_endpoint"] = {"ip": f["DestinationIp"], "port": int(f.get("DestinationPort", "0") or 0)}
            out["connection_info"] = {"protocol_name": f.get("Protocol", "tcp"), "direction": "outbound"}
            out["device"] = device
            return out
        return None
    if channel == "Security" and eid in (4624, 4625):
        inserts = rec.get("StringInserts") or []
        user = inserts[5] if len(inserts) > 5 else "unknown"
        ip_index = 18 if eid == 4624 else 19
        ip = inserts[ip_index] if len(inserts) > ip_index else ""
        out = ocsf.new_event(ocsf.AUTHENTICATION, 1, time=ts, product="windows-security", labels=labels,
                             uid=f"{host}-security-{rec.get('EventRecordID')}")
        out["status_id"] = ocsf.STATUS_SUCCESS if eid == 4624 else ocsf.STATUS_FAILURE
        out["user"] = {"name": str(user)}
        out["device"] = device
        out["dst_endpoint"] = {"hostname": host}
        if ip and ip not in ("-", "::1", "127.0.0.1"):
            out["src_endpoint"] = {"ip": str(ip)}
        out["is_remote"] = bool(ip and ip not in ("-", "::1", "127.0.0.1"))
        return out
    return None
