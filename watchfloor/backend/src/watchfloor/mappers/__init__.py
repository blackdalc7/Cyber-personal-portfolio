"""Edge mappers: each source keeps its own schema and is translated to OCSF here."""

from __future__ import annotations

from typing import Any

from .. import ocsf
from .ecs import map_ecs, map_ecs_alert, map_ecs_event
from .sources import map_edr_record, map_incident, map_meta_alert, map_tetragon, map_winlog

__all__ = ["SOURCES", "map_ecs", "map_ecs_alert", "map_ecs_event", "map_edr_record", "map_incident",
           "map_meta_alert", "map_record", "map_tetragon", "map_winlog"]

SOURCES = ("siem", "edr", "edr-raw", "triage", "soar", "tetragon", "winlog", "ocsf")


def map_record(source: str, record: dict[str, Any], *, scenario: str | None = None,
               host: str | None = None, run_time: Any = None) -> dict[str, Any] | None:
    """Translate one record from ``source`` to a validated OCSF event, or ``None`` to skip it.

    Raises:
        ocsf.ContractError: if the mapped document breaks the contract (a mapper bug).
        ValueError: for an unknown source.
    """
    if source == "siem":
        out = map_ecs(record, product="realtime-siem", scenario=scenario)
    elif source == "edr":
        out = map_ecs(record, product="edr-canary", scenario=scenario)
    elif source == "edr-raw":
        out = map_edr_record(record, host=host or "ws01", scenario=scenario)
    elif source == "triage":
        out = map_meta_alert(record, run_time=run_time, scenario=scenario)
    elif source == "soar":
        out = map_incident(record, scenario=scenario)
    elif source == "tetragon":
        out = map_tetragon(record, scenario=scenario)
    elif source == "winlog":
        out = map_winlog(record, scenario=scenario)
    elif source == "ocsf":
        out = record
    else:
        raise ValueError(f"unknown source {source!r}; expected one of {', '.join(SOURCES)}")
    return ocsf.validate(out) if out is not None else None
