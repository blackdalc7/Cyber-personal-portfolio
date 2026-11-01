"""Windows event log XML exports (``wevtutil qe <log> /f:xml /e:Events`` or Event Viewer "Save as XML").

Handles Sysmon Event ID 1 (process create) and Security Event ID 4688 (process
creation, with command-line auditing enabled). 4688 uses different field names and hex
process IDs; both are normalised to the Sigma process_creation taxonomy so one rule set
covers either source. Parsed with defusedxml: exports are files from other machines.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from defusedxml import ElementTree as SafeET

from .base import LogFormatError, parse_time

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
SYSMON = "Microsoft-Windows-Sysmon"
SECURITY = "Microsoft-Windows-Security-Auditing"


def _int(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return None


def _event(el: Any, source: str) -> dict[str, Any] | None:
    system = el.find(f"{NS}System")
    if system is None:
        return None
    provider = (system.find(f"{NS}Provider").get("Name", "") if system.find(f"{NS}Provider") is not None else "")
    eid = (system.findtext(f"{NS}EventID") or "").strip()
    created = system.find(f"{NS}TimeCreated")
    computer = (system.findtext(f"{NS}Computer") or "").strip()
    data = {d.get("Name", ""): (d.text or "") for d in el.iter(f"{NS}Data")}
    if created is None or not created.get("SystemTime"):
        raise LogFormatError(f"{source}: event without TimeCreated")
    host = computer.split(".")[0].lower()
    base = {"Computer": computer, "_time": parse_time(created.get("SystemTime")), "_host": host,
            "_logsource": {"category": "process_creation", "product": "windows"}, "_source": source}

    if provider == SYSMON and eid == "1":
        ev = {k: v for k, v in data.items() if v != ""}
        for key in ("ProcessId", "ParentProcessId"):
            if key in ev:
                ev[key] = _int(ev[key])
        return {**ev, **base, "EventID": 1}
    if provider == SECURITY and eid == "4688":
        user, domain = data.get("SubjectUserName", ""), data.get("SubjectDomainName", "")
        ev = {
            "EventID": 4688,
            "Image": data.get("NewProcessName") or None,
            "CommandLine": data.get("CommandLine") or None,
            "ParentImage": data.get("ParentProcessName") or None,
            "ProcessId": _int(data.get("NewProcessId")),
            "ParentProcessId": _int(data.get("ProcessId")),
            "User": f"{domain}\\{user}" if domain and user else (user or None),
            "IntegrityLevel": data.get("MandatoryLabel") or None,
        }
        return {**{k: v for k, v in ev.items() if v is not None}, **base}
    return None


def read_windows_xml(path: str | Path) -> list[dict[str, Any]]:
    """Read a ``wevtutil`` XML export (with or without an ``<Events>`` root) into events.

    The XML is parsed with defusedxml.
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8-sig")
    try:
        root = SafeET.fromstring(text)
    except SafeET.ParseError:
        # wevtutil without /e:Events emits bare <Event> siblings; wrap them.
        root = SafeET.fromstring(f"<Events>{text}</Events>")
    elements = [root] if root.tag == f"{NS}Event" else list(root.iter(f"{NS}Event"))
    events = []
    for i, el in enumerate(elements, start=1):
        ev = _event(el, f"winxml:{path.name}:{i}")
        if ev is not None:
            events.append(ev)
    return events
