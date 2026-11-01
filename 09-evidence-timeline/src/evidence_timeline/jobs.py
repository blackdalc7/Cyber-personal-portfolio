"""One collection job: endpoint artifacts (Velociraptor or a local Hayabusa CSV) + hub telemetry -> package."""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from collections.abc import Callable
from concurrent.futures import Executor, ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import httpx

from . import hayabusa
from .config import Settings
from .package import write_package
from .timeline import highlights as pick_highlights
from .timeline import hub_events, merge, to_csv, to_jsonl, triage_rows
from .velociraptor import Velociraptor, VelociraptorError, grpc_query

log = logging.getLogger("evidence_timeline.jobs")


INCIDENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")


@dataclass(frozen=True)
class CollectRequest:
    incident_id: str
    host: str
    around_ms: int | None = None
    requested_by: str | None = None
    decided_by: str | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        # The incident id becomes a directory name and the host a VQL variable: both are checked here, whatever
        # the caller (HTTP or CLI) already did.
        if not INCIDENT_ID.match(self.incident_id) or ".." in self.incident_id:
            raise ValueError(f"invalid incident id {self.incident_id!r}")
        if not HOST.match(self.host):
            raise ValueError(f"invalid host {self.host!r}")


@dataclass
class Job:
    incident_id: str
    host: str
    status: str = "queued"  # queued | running | done | failed
    queued_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    package: str | None = None
    error: str | None = None
    rows: int = 0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _jsonl(rows: list[dict[str, Any]]) -> str:
    return "".join(json.dumps(r, sort_keys=True, default=str) + "\n" for r in rows)


def collect(req: CollectRequest, settings: Settings, *, velociraptor: Velociraptor | None = None,
            http: httpx.Client | None = None, now_ms: int | None = None) -> tuple[Path, int]:
    """Run one collection and write the package. Returns ``(package_dir, timeline_rows)``."""
    now_ms = now_ms or int(time.time() * 1000)
    center = req.around_ms or now_ms
    since, until = center - settings.window_before_s * 1000, max(center + settings.window_after_s * 1000, now_ms)
    files: dict[str, str] = {}
    sources: list[str] = []
    warnings: list[str] = []
    endpoint_rows: list[dict[str, Any]] = []
    collection: dict[str, Any] = {"mode": settings.mode}

    if settings.mode == "velociraptor":
        velo = velociraptor or Velociraptor(grpc_query(settings.velociraptor_api_config, settings.collect_timeout_s))
        artifacts = [settings.hayabusa_artifact, *settings.triage_artifacts]
        for art, rows, meta in velo.collect_all(req.host, artifacts, settings.collect_timeout_s,
                                                settings.max_rows_per_source):
            collection.update(meta, artifacts=artifacts)
            files[f"raw/{art}.jsonl"] = _jsonl(rows)
            sources.append(f"velociraptor:{art}")
            if art == settings.hayabusa_artifact:
                endpoint_rows += hayabusa.to_rows(rows, req.host)
            else:
                endpoint_rows += triage_rows(art, rows, req.host, now_ms)
    else:
        csv_path = settings.local_dir / f"{req.host}.csv"
        if not csv_path.is_file():
            raise FileNotFoundError(f"local mode: no Hayabusa timeline at {csv_path}")
        files["raw/hayabusa.csv"] = csv_path.read_text(encoding="utf-8-sig")
        endpoint_rows += hayabusa.read_csv(csv_path, req.host, settings.max_rows_per_source)
        sources.append(f"hayabusa-csv:{csv_path.name}")

    hub_rows: list[dict[str, Any]] = []
    if settings.hub_url:
        client = http or httpx.Client(timeout=30.0)
        try:
            hub_rows = hub_events(client, settings.hub_url, settings.hub_token, req.host, since, until)
            sources.append("watchfloor:/api/events")
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            warnings.append(f"watchfloor telemetry unavailable: {type(exc).__name__}")
        finally:
            if http is None:
                client.close()

    rows = merge(endpoint_rows, hub_rows)
    files["timeline.csv"] = to_csv(rows)
    files["timeline.jsonl"] = to_jsonl(rows)
    manifest = {"host": req.host, "sources": sources, "timeline_rows": len(rows),
                "highlights": pick_highlights(rows), "requested_by": req.requested_by,
                "decided_by": req.decided_by, "reason": req.reason, "window": {"since": since, "until": until},
                "collection": collection, "warnings": warnings, "simulated": False, "tool": "09-evidence-timeline"}
    return write_package(settings.out_dir, req.incident_id, files, manifest), len(rows)


class JobStore:
    """At most one job per incident; runs in a small worker pool; status is kept in memory and on disk."""

    def __init__(self, settings: Settings, runner: Callable[[CollectRequest], tuple[Path, int]] | None = None,
                 executor: Executor | None = None) -> None:
        self.settings = settings
        self._run = runner or (lambda req: collect(req, settings))
        self._executor = executor or ThreadPoolExecutor(max_workers=2, thread_name_prefix="collect")
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def get(self, incident_id: str) -> Job | None:
        return self._jobs.get(incident_id)

    def submit(self, req: CollectRequest, force: bool = False) -> tuple[Job, bool]:
        """Queue a job. Returns ``(job, created)``; an existing queued/running/done job is returned unless forced."""
        with self._lock:
            cur = self._jobs.get(req.incident_id)
            if cur and (cur.status in ("queued", "running") or (cur.status == "done" and not force)):
                return cur, False
            job = Job(incident_id=req.incident_id, host=req.host)
            self._jobs[req.incident_id] = job
        self._executor.submit(self._work, job, req)
        return job, True

    def _work(self, job: Job, req: CollectRequest) -> None:
        job.status = "running"
        try:
            path, n = self._run(req)
            job.package, job.rows, job.status = str(path), n, "done"
        except (VelociraptorError, OSError, ValueError, httpx.HTTPError, RuntimeError) as exc:
            job.status, job.error = "failed", f"{type(exc).__name__}: {exc}"[:500]
            log.error("collection for %s failed: %s", req.incident_id, job.error)
        finally:
            job.finished_at = time.time()
            self._persist(job)

    def _persist(self, job: Job) -> None:
        d = self.settings.out_dir / ".jobs"
        try:
            d.mkdir(parents=True, exist_ok=True)
            (d / f"{job.incident_id}.json").write_text(json.dumps(job.as_dict()), encoding="utf-8")
        except OSError as exc:
            log.warning("could not persist job status: %s", exc)

    def shutdown(self) -> None:
        self._executor.shutdown(wait=True)
