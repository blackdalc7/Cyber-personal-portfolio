"""Merge Hayabusa detections, endpoint triage and Watchfloor telemetry into one sorted timeline."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

import httpx

COLUMNS = ("time", "time_utc", "source", "host", "level", "title", "details", "ref", "tags")
SEVERITY = {0: "informational", 1: "informational", 2: "low", 3: "medium", 4: "high", 5: "critical", 6: "critical"}
LEVEL_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
FINDING_CLASSES = {2004, 2005}


def hub_events(client: httpx.Client, hub_url: str, token: str, host: str, since_ms: int, until_ms: int,
               limit: int = 2000) -> list[dict[str, Any]]:
    """Watchfloor's events and findings for ``host`` in the window, as timeline rows."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    r = client.get(f"{hub_url}/api/events", headers=headers,
                   params={"hostname": host, "since": since_ms, "until": until_ms, "limit": limit})
    r.raise_for_status()
    out = []
    for e in r.json():
        finding = e.get("class_uid") in FINDING_CLASSES
        title = (e.get("finding_title") if finding else None) or (
            f"{e.get('process_name')}: {e.get('cmd_line')}" if e.get("cmd_line") else None) or e.get("message") \
            or e.get("file_path") or (f"{e['process_name']} started" if e.get("process_name") else None) \
            or f"OCSF class {e.get('class_uid')}"
        out.append({"time": int(e["time"]), "source": f"watchfloor:{e.get('product') or 'unknown'}", "host": host,
                    "title": str(title)[:500],
                    "level": SEVERITY.get(int(e.get("severity_id") or 0), "informational") if finding
                    else "informational",
                    "details": str(e.get("message") or "")[:2000] if finding else str(e.get("file_path") or ""),
                    "ref": str(e.get("uid") or ""), "tags": ",".join(e.get("techniques") or [])})
    return out


def triage_rows(artifact: str, rows: list[dict[str, Any]], host: str, collected_ms: int) -> list[dict[str, Any]]:
    """Point-in-time artifacts (process list, connections, autoruns) as timeline rows at collection time."""
    def title(r: dict[str, Any]) -> str:
        if "Pid" in r and "Name" in r:
            return f"process {r['Name']} (pid {r['Pid']}, ppid {r.get('Ppid', '?')})"
        if "Raddr" in r or "Laddr" in r:
            return f"{r.get('Name', '?')} {r.get('Laddr', '')} -> {r.get('Raddr', '')} {r.get('Status', '')}".strip()
        if "Entry" in r or "Entry Location" in r:
            return f"autorun {r.get('Entry') or ''} @ {r.get('Entry Location') or ''}".strip()
        return artifact

    out = []
    for r in rows:
        details = r.get("CommandLine") or r.get("Image Path") or r.get("Launch String") or ""
        out.append({"time": collected_ms, "source": artifact, "host": host, "title": title(r)[:500],
                    "level": "informational", "details": str(details)[:2000], "ref": "", "tags": ""})
    return out


def iso(ms: int) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def merge(*sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = [dict(r, time_utc=iso(r["time"])) for src in sources for r in src]
    rows.sort(key=lambda r: (r["time"], -LEVEL_RANK.get(r["level"], 0), r["source"], r["title"]))
    return rows


def highlights(rows: list[dict[str, Any]], n: int = 12) -> list[dict[str, Any]]:
    """The rows an analyst reads first: high/critical Hayabusa hits and Watchfloor findings, in time order."""
    keep = [r for r in rows if LEVEL_RANK.get(r["level"], 0) >= 3
            or (r["source"].startswith("watchfloor:") and r["level"] != "informational")]
    keep.sort(key=lambda r: (-LEVEL_RANK.get(r["level"], 0), r["time"]))
    top = sorted(keep[:n], key=lambda r: r["time"])
    return [{"time": r["time_utc"], "source": r["source"], "title": r["title"], "level": r["level"]} for r in top]


def to_csv(rows: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=COLUMNS, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for r in rows:
        # Neutralise spreadsheet formula injection: endpoint data is attacker-controlled.
        w.writerow({k: ("'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@") else v)
                    for k, v in r.items()})
    return buf.getvalue()


def to_jsonl(rows: list[dict[str, Any]]) -> str:
    return "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in rows)
