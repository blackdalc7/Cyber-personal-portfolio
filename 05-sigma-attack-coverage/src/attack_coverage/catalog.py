"""ATT&CK technique catalogue (what detection content should exist) and exercise manifests (what was run).

catalog.yml::

    techniques:
      - id: T1033
        name: System Owner/User Discovery
        tactic: discovery
        expected_rules: [<sigma rule id>, ...]

exercise.yml (written by the red team or the emulation tool that ran the exercise)::

    name: Q4 purple-team exercise
    steps:
      - {technique: T1033, host: ws01, platform: windows,
         start: "2026-10-26T09:00:00Z", end: "2026-10-26T09:00:20Z", procedure: "whoami /all"}
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from .logs.base import LogFormatError, parse_time

_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
TACTICS = {"reconnaissance", "resource-development", "initial-access", "execution", "persistence",
           "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
           "collection", "command-and-control", "exfiltration", "impact"}


class CatalogError(ValueError):
    """Raised when the technique catalogue or an exercise file is invalid."""


@dataclass(frozen=True)
class Technique:
    """One MITRE ATT&CK technique and the Sigma rule ids expected to detect it."""
    id: str
    name: str
    tactic: str
    expected_rules: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExerciseStep:
    """One purple-team action: a technique run on a host between ``start`` and ``end``."""
    technique: str
    host: str
    platform: str
    start: datetime
    end: datetime
    procedure: str = ""


@dataclass
class Exercise:
    """A named purple-team exercise made of ordered steps."""
    name: str
    steps: list[ExerciseStep] = field(default_factory=list)


def _yaml(path: str | Path) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise CatalogError(f"{path}: expected a YAML mapping")
    return data


def load_catalog(path: str | Path) -> dict[str, Technique]:
    """Load and validate the technique catalogue, keyed by technique id.

    Raises:
        CatalogError: for a malformed id, unknown tactic or duplicate technique.
    """
    out: dict[str, Technique] = {}
    for i, t in enumerate(_yaml(path).get("techniques") or []):
        where = f"{path}: techniques[{i}]"
        tid = str(t.get("id", "")).upper()
        if not _TECHNIQUE.match(tid):
            raise CatalogError(f"{where}: id must look like T1059 or T1059.001")
        tactic = str(t.get("tactic", "")).lower()
        if tactic not in TACTICS:
            raise CatalogError(f"{where}: unknown tactic {tactic!r}")
        if tid in out:
            raise CatalogError(f"{where}: duplicate technique {tid}")
        out[tid] = Technique(tid, str(t.get("name", tid)), tactic, tuple(str(r) for r in t.get("expected_rules") or ()))
    return out


def load_exercise(path: str | Path, catalog: dict[str, Technique]) -> Exercise:
    """Load an exercise file and check every step against ``catalog``.

    Raises:
        CatalogError: for unknown techniques, missing fields or bad time windows.
    """
    data = _yaml(path)
    ex = Exercise(name=str(data.get("name", Path(path).stem)))
    for i, s in enumerate(data.get("steps") or []):
        where = f"{path}: steps[{i}]"
        tid = str(s.get("technique", "")).upper()
        if tid not in catalog:
            raise CatalogError(f"{where}: technique {tid or '?'} is not in the catalogue")
        for req in ("host", "start", "end"):
            if not s.get(req):
                raise CatalogError(f"{where}: '{req}' is required")
        try:
            start, end = parse_time(s["start"]), parse_time(s["end"])
        except LogFormatError as exc:
            raise CatalogError(f"{where}: {exc}") from exc
        if end < start:
            raise CatalogError(f"{where}: end is before start")
        host = str(s["host"]).split(".")[0].lower()
        ex.steps.append(ExerciseStep(tid, host, str(s.get("platform", "windows")).lower(),
                                     start, end, str(s.get("procedure", ""))))
    if not ex.steps:
        raise CatalogError(f"{path}: exercise has no steps")
    return ex
