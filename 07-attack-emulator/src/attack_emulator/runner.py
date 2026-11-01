"""Run a campaign: execute each test, wait for the platform's verdict, clean up, move on."""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .campaign import AtomicTest, Campaign
from .config import Settings
from .executors import ExecResult, Executor
from .poller import HubClient, Observation, wait_for_detection

log = logging.getLogger("attack_emulator")


@dataclass
class Cell:
    technique: str
    name: str
    tactic: str
    target: str
    hostname: str
    test: str
    executor: str
    outcome: str  # detected | prevented | telemetry_only | missed | error | skipped
    started: int
    ended: int
    ttd_ms: int | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    telemetry_events: int = 0
    polls: int = 0
    rc: int | None = None
    error: str | None = None
    cleanup_rc: int | None = None
    output_tail: dict[str, str] = field(default_factory=dict)


@dataclass
class RunResult:
    run_id: str
    campaign: str
    started: int
    finished: int
    cells: list[Cell]
    dry_run: bool = False


def new_run_id(now: datetime | None = None) -> str:
    t = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    return f"run-{t}-{uuid.uuid4().hex[:6]}"


def _cell(test: AtomicTest, campaign: Campaign, res: ExecResult, outcome: str, obs: Observation | None) -> Cell:
    tgt = campaign.targets[test.target]
    return Cell(technique=test.technique, name=test.name, tactic=test.tactic, target=tgt.name, hostname=tgt.hostname,
                test=test.key, executor=tgt.executor, outcome=outcome, started=res.started_ms, ended=res.ended_ms,
                ttd_ms=obs.ttd_ms if obs else None, findings=obs.findings if obs else [],
                telemetry_events=obs.telemetry_events if obs else 0, polls=obs.polls if obs else 0, rc=res.rc,
                error=res.error, output_tail=res.tail(800))


def run_campaign(campaign: Campaign, settings: Settings, executors: dict[str, Executor], hub: HubClient | None, *,
                 run_id: str, only: set[str] | None = None, sleep: Callable[[float], None] | None = None,
                 clock: Callable[[], float] | None = None) -> RunResult:
    sleep = sleep or time.sleep
    clock = clock or time.time
    started = int(clock() * 1000)
    cells: list[Cell] = []
    tests = [t for t in campaign.tests if not only or t.technique in only or t.technique.split(".")[0] in only]
    for i, test in enumerate(tests):
        target = campaign.targets[test.target]
        executor = executors[target.executor]
        log.info("[%d/%d] %s on %s via %s", i + 1, len(tests), test.key, target.name, target.executor)
        res = executor.run(test, target)
        obs: Observation | None = None
        if not res.executed:
            outcome = "error" if res.error else "skipped"
        elif res.prevented:
            outcome = "prevented"
        elif res.error and res.rc not in (0, None):
            outcome = "error"
        elif hub is None:
            outcome = "skipped"
        else:
            obs = wait_for_detection(hub, technique=test.technique, hostname=target.hostname, start_ms=res.started_ms,
                                     timeout_s=settings.poll_timeout_s, base_s=settings.poll_base_s,
                                     max_s=settings.poll_max_s, window_s=settings.window_s, clock=clock, sleep=sleep,
                                     match=test.telemetry_match)
            outcome = obs.outcome
        cell = _cell(test, campaign, res, outcome, obs)
        if test.cleanup and res.executed:
            cleaned = executor.cleanup(test, target)
            cell.cleanup_rc = cleaned.rc if cleaned else None
        log.info("    -> %s%s", outcome, f" in {cell.ttd_ms} ms" if cell.ttd_ms is not None else "")
        cells.append(cell)
        if i < len(tests) - 1 and campaign.settle_s and res.executed:
            sleep(campaign.settle_s)  # keep each technique's scoring window clear of the next one
    dry = all(c.outcome == "skipped" for c in cells)
    return RunResult(run_id=run_id, campaign=campaign.name, started=started, finished=int(clock() * 1000),
                     cells=cells, dry_run=dry)
