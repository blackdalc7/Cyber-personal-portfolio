"""Scenarios: recorded attack datasets, their kill-chain stages, scoring and replay.

A scenario directory holds ``scenario.yml`` (stages with ATT&CK techniques and the
time each stage began) and ``events.ndjson`` (OCSF events in time order). The same
:func:`score_stages` logic scores a replayed dataset and a live 07 emulation run, so
the dashboard's Scenario mode and the emulator's pass/fail matrix always agree.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import ocsf

logger = logging.getLogger("watchfloor.scenarios")

DETECTED, TELEMETRY_ONLY, MISSED = "detected", "telemetry_only", "missed"


@dataclass
class Stage:
    """One kill-chain stage: the techniques it exercises and when it began (epoch ms)."""
    id: str
    name: str
    tactic: str
    techniques: list[str]
    start: int
    host: str | None = None
    description: str = ""


@dataclass
class Scenario:
    """A recorded dataset plus its stage definitions."""
    id: str
    title: str
    summary: str
    provenance: str
    stages: list[Stage]
    path: Path
    hosts: list[str] = field(default_factory=list)
    simulated_parts: list[str] = field(default_factory=list)

    def events(self) -> list[dict[str, Any]]:
        """Load the OCSF events, sorted by time."""
        out = []
        with (self.path / "events.ndjson").open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    out.append(json.loads(line))
        return sorted(out, key=lambda d: d["time"])

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe description for the API and UI."""
        return {"id": self.id, "title": self.title, "summary": self.summary, "provenance": self.provenance,
                "hosts": self.hosts, "simulated_parts": self.simulated_parts,
                "stages": [s.__dict__ for s in self.stages]}


def load_scenario(path: Path) -> Scenario:
    """Read ``scenario.yml`` from ``path``."""
    meta = yaml.safe_load((Path(path) / "scenario.yml").read_text(encoding="utf-8"))
    stages = [Stage(id=s["id"], name=s["name"], tactic=s["tactic"], techniques=list(s["techniques"]),
                    start=ocsf.to_epoch_ms(s["start"]), host=s.get("host"), description=s.get("description", ""))
              for s in meta["stages"]]
    return Scenario(id=meta["id"], title=meta["title"], summary=meta.get("summary", ""),
                    provenance=meta.get("provenance", ""), stages=stages, path=Path(path),
                    hosts=list(meta.get("hosts", [])), simulated_parts=list(meta.get("simulated_parts", [])))


def list_scenarios(root: Path) -> list[Scenario]:
    """Every scenario under ``root`` (one sub-directory each), sorted by id."""
    root = Path(root)
    if not root.is_dir():
        return []
    return sorted((load_scenario(p) for p in root.iterdir() if (p / "scenario.yml").is_file()),
                  key=lambda s: s.id)


def technique_matches(stage_technique: str, finding_technique: str) -> bool:
    """True if a finding's technique satisfies a stage's: equal, or parent/sub-technique of it."""
    a, b = stage_technique.upper(), finding_technique.upper()
    return a == b or a.split(".")[0] == b or b.split(".")[0] == a


def score_stages(stages: Iterable[Stage], events: Iterable[dict[str, Any]], window_ms: int = 15 * 60 * 1000
                 ) -> list[dict[str, Any]]:
    """Score each stage as detected, telemetry-only or missed.

    * **detected**: a Detection Finding with a matching technique within ``window_ms``
      after the stage began. ``ttd_ms`` is the delay to the first such finding.
    * **telemetry_only**: no finding, but activity events from the stage's host exist in
      the window, so a rule could have fired.
    * **missed**: neither.
    """
    events = list(events)
    findings = [e for e in events if e["class_uid"] == ocsf.DETECTION_FINDING]
    activity = [e for e in events if e["class_uid"] not in ocsf.FINDING_CLASSES]
    results = []
    for st in stages:
        end = st.start + window_ms
        hits = []
        for f in findings:
            if not (st.start - 1000 <= f["time"] <= end):
                continue
            techs = ocsf.techniques_of(f)
            if any(technique_matches(t, ft) for t in st.techniques for ft in techs):
                hits.append(f)
        hits.sort(key=lambda f: f["time"])
        telemetry = [e for e in activity if st.start - 1000 <= e["time"] <= end
                     and (st.host is None or (e.get("device") or {}).get("hostname") == st.host)]
        outcome = DETECTED if hits else TELEMETRY_ONLY if telemetry else MISSED
        results.append({
            "stage": st.id, "name": st.name, "tactic": st.tactic, "techniques": st.techniques,
            "start": st.start, "outcome": outcome,
            "ttd_ms": max(0, hits[0]["time"] - st.start) if hits else None,
            "findings": [{"uid": f["metadata"]["uid"], "title": f["finding_info"]["title"],
                          "product": f["metadata"]["product"]["name"], "time": f["time"]} for f in hits[:10]],
            "telemetry_events": len(telemetry),
        })
    return results


def rebase(events: list[dict[str, Any]], new_start_ms: int) -> tuple[list[dict[str, Any]], int]:
    """Shift every event so the first one happens at ``new_start_ms``; returns events and the shift."""
    if not events:
        return [], 0
    shift = new_start_ms - events[0]["time"]
    out = []
    for e in events:
        d = json.loads(json.dumps(e))
        d["time"] = e["time"] + shift
        d["metadata"]["uid"] = f"{e['metadata']['uid']}@{new_start_ms}"
        out.append(d)
    return out, shift


def replay(scenario: Scenario, publish: Callable[[dict[str, Any]], Any], *, speed: float = 60.0,
           rebase_to_now: bool = True, max_gap_s: float = 5.0, sleep: Callable[[float], None] = time.sleep,
           clock: Callable[[], float] = time.time) -> int:
    """Publish a scenario's events in order, compressing time by ``speed``.

    Gaps are capped at ``max_gap_s`` real seconds so long quiet periods do not stall a
    demo. Returns the number of events published.
    """
    events = scenario.events()
    if rebase_to_now:
        events, _ = rebase(events, int(clock() * 1000))
    prev = None
    for e in events:
        if prev is not None and speed > 0:
            gap = (e["time"] - prev) / 1000 / speed
            if gap > 0:
                sleep(min(gap, max_gap_s))
        publish(e)
        prev = e["time"]
    logger.info("Replayed %d events from %s", len(events), scenario.id)
    return len(events)
