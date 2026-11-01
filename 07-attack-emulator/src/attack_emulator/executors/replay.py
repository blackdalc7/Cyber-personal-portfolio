"""Replay executor: send a technique's *recorded telemetry* to the hub instead of running the technique.

It exists so the full loop (telemetry -> 08's rules -> finding -> scoring) can be demonstrated and tested without
a lab. It only ever sends activity events: recorded findings are dropped, so a detection can only come from the
platform's own rules, never from the fixture.
"""

from __future__ import annotations

import copy
import json
import uuid
from pathlib import Path
from typing import Any

import httpx

from ..campaign import AtomicTest, Target
from .base import ExecResult, now_ms

FINDING_CLASSES = {2004, 2005}


def load_fixture(directory: Path, technique: str) -> list[dict[str, Any]]:
    path = Path(directory) / f"{technique}.ndjson"
    if not path.is_file():
        raise FileNotFoundError(f"no replay fixture for {technique} in {directory}")
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [r for r in rows if r.get("class_uid") not in FINDING_CLASSES]


def rebase(events: list[dict[str, Any]], *, start_ms: int, hostname: str, run_label: str) -> list[dict[str, Any]]:
    """Shift times so the first event lands at ``start_ms``, set the target host and fresh uids."""
    if not events:
        return []
    t0 = min(int(e["time"]) for e in events)
    out = []
    for e in events:
        d = copy.deepcopy(e)
        d["time"] = start_ms + (int(e["time"]) - t0)
        d.setdefault("metadata", {})["uid"] = str(uuid.uuid4())
        d["metadata"]["labels"] = sorted({*d["metadata"].get("labels", []), run_label})
        d.setdefault("device", {})["hostname"] = hostname
        out.append(d)
    return out


class ReplayExecutor:
    """Posts a technique's recorded OCSF events to the hub instead of running anything, so CI can score a campaign."""
    def __init__(self, hub_url: str, ingest_token: str, fixtures: Path, run_id: str,
                 client: httpx.Client | None = None) -> None:
        if not ingest_token:
            raise ValueError("the replay executor posts to /api/ingest/ocsf: set EMU_INGEST_TOKEN")
        self._url = f"{hub_url.rstrip('/')}/api/ingest/ocsf"
        self._token = ingest_token
        self._fixtures = Path(fixtures)
        self._label = f"emulation:{run_id}"
        self._client = client or httpx.Client(timeout=15.0)

    def run(self, test: AtomicTest, target: Target) -> ExecResult:
        """Rebase the technique's fixture onto now and the target host, then post it to the hub's ingest API."""
        start = now_ms()
        try:
            events = rebase(load_fixture(self._fixtures, test.technique), start_ms=start, hostname=target.hostname,
                            run_label=self._label)
        except (OSError, ValueError, KeyError) as exc:
            return ExecResult(start, now_ms(), 2, command=f"replay {test.technique}", error=str(exc), executed=False)
        body = "\n".join(json.dumps(e, separators=(",", ":")) for e in events)
        try:
            r = self._client.post(self._url, content=body.encode(), headers={
                "Authorization": f"Bearer {self._token}", "Content-Type": "application/x-ndjson"})
        except httpx.HTTPError as exc:
            return ExecResult(start, now_ms(), 255, command=f"replay {test.technique}", error=type(exc).__name__)
        ok = r.status_code < 300
        return ExecResult(start, now_ms(), 0 if ok else r.status_code, r.text[:500], "",
                          f"replay {len(events)} recorded events for {test.technique}",
                          error=None if ok else f"hub answered {r.status_code}")

    def cleanup(self, test: AtomicTest, target: Target) -> ExecResult | None:
        return None

    def close(self) -> None:
        self._client.close()
