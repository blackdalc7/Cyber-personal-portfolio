"""Elastic Common Schema NDJSON (Elastic/OpenSearch exports, Winlogbeat, Auditbeat, Project 01 output)."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .base import LogFormatError, parse_time

logger = logging.getLogger("attack_coverage.logs.ecs")


def _get(doc: Mapping[str, Any], dotted: str) -> Any:
    if dotted in doc:            # flattened exports use literal dotted keys
        return doc[dotted]
    node: Any = doc
    for part in dotted.split("."):
        if not isinstance(node, Mapping):
            return None
        node = node.get(part)
    return node


def _as_list(v: Any) -> list[str]:
    if v is None:
        return []
    return [str(x).lower() for x in (v if isinstance(v, list) else [v])]


def ecs_to_sigma(doc: Mapping[str, Any]) -> dict[str, Any] | None:
    """Map an ECS process-start document to Sigma process_creation fields. Other documents → None."""
    if "process" not in _as_list(_get(doc, "event.category")) or "start" not in _as_list(_get(doc, "event.type")):
        return None
    ts = _get(doc, "@timestamp")
    if ts is None:
        raise LogFormatError("ECS document without @timestamp")
    os_type = str(_get(doc, "host.os.type") or _get(doc, "host.os.family") or "").lower()
    product = "windows" if os_type.startswith("win") else (os_type or "linux")
    user = _get(doc, "user.name")
    domain = _get(doc, "user.domain")
    host = str(_get(doc, "host.hostname") or _get(doc, "host.name") or "").lower()
    args = _get(doc, "process.args")
    cmd = _get(doc, "process.command_line") or (" ".join(map(str, args)) if isinstance(args, list) else None)
    event: dict[str, Any] = {
        "Image": _get(doc, "process.executable") or _get(doc, "process.name"),
        "CommandLine": cmd,
        "OriginalFileName": _get(doc, "process.pe.original_file_name"),
        "ProcessId": _get(doc, "process.pid"),
        "ParentImage": _get(doc, "process.parent.executable") or _get(doc, "process.parent.name"),
        "ParentCommandLine": _get(doc, "process.parent.command_line"),
        "ParentProcessId": _get(doc, "process.parent.pid"),
        "User": f"{domain}\\{user}" if domain and user else user,
        "CurrentDirectory": _get(doc, "process.working_directory"),
        "Computer": host,
        "_logsource": {"category": "process_creation", "product": product},
        "_time": parse_time(ts),
        "_host": host,
    }
    return {k: v for k, v in event.items() if v is not None}


def read_ecs_ndjson(path: str | Path) -> list[dict[str, Any]]:
    """Read ECS NDJSON and map each document to Sigma's Windows field names.

    Raises:
        LogFormatError: naming the line with invalid JSON.
    """
    path = Path(path)
    events = []
    with path.open(encoding="utf-8-sig") as fh:
        for n, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError as exc:
                raise LogFormatError(f"{path}:{n}: invalid JSON ({exc.msg})") from exc
            if isinstance(doc, Mapping) and "_source" in doc and isinstance(doc["_source"], Mapping):
                doc = doc["_source"]      # raw Elasticsearch hit
            if not isinstance(doc, Mapping):
                raise LogFormatError(f"{path}:{n}: expected a JSON object")
            ev = ecs_to_sigma(doc)
            if ev is not None:
                ev["_source"] = f"ecs:{path.name}:{n}"
                events.append(ev)
    return events
