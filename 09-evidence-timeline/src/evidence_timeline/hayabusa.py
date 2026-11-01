"""Hayabusa results, from its CSV timeline or from the Velociraptor artifact that runs it, as timeline rows."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LEVELS = {"crit": "critical", "critical": "critical", "high": "high", "med": "medium", "medium": "medium",
          "low": "low", "info": "informational", "informational": "informational"}


def parse_time(value: Any) -> int | None:
    """Hayabusa writes ``2026-10-26 09:00:12.000 +00:00``; Velociraptor rows carry ISO 8601. Returns epoch ms."""
    if value is None or value == "":
        return None
    if isinstance(value, int | float):
        return int(value * 1000) if value < 1e11 else int(value)
    text = str(value).strip().replace("Z", "+00:00")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f %z", "%Y-%m-%d %H:%M:%S %z"):
        try:
            return int(datetime.strptime(text, fmt).timestamp() * 1000)
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def _get(row: dict[str, Any], *names: str) -> Any:
    for n in names:
        if row.get(n) not in (None, ""):
            return row[n]
    return None


def to_rows(records: list[dict[str, Any]], host: str) -> list[dict[str, Any]]:
    """Convert Hayabusa CSV or JSONL records into timeline rows, skipping any without a time or rule title."""
    out = []
    for r in records:
        t = parse_time(_get(r, "Timestamp", "timestamp", "EventTime"))
        title = _get(r, "RuleTitle", "Rule Title", "rule_title")
        if t is None or not title:
            continue
        details = _get(r, "Details", "details", "Detail")
        tags = _get(r, "MitreTags", "MitreTactics", "Tags") or ""
        out.append({
            "time": t, "source": "hayabusa", "host": str(_get(r, "Computer", "computer") or host),
            "title": str(title), "level": LEVELS.get(str(_get(r, "Level", "level") or "").lower(), "informational"),
            "details": str(details)[:2000] if details else "",
            "ref": f"{_get(r, 'Channel', 'channel') or ''}:{_get(r, 'EventID', 'event_id') or ''}".strip(":"),
            "tags": str(tags),
        })
    return out


def read_csv(path: Path, host: str, max_rows: int) -> list[dict[str, Any]]:
    with Path(path).open(newline="", encoding="utf-8-sig") as fh:
        records = []
        for i, row in enumerate(csv.DictReader(fh)):
            if i >= max_rows:
                break
            records.append(row)
    return to_rows(records, host)
