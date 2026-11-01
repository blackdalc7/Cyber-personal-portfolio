"""Run the compiled rules over new lake data and send Detection Findings to the hub.

Each cycle queries ``[watermark - overlap, now)``. The overlap re-reads the last few minutes so events that reach
the lake late (the lake writer batches) are not skipped; deterministic finding uids plus a small "already emitted"
set stop the overlap from producing duplicates. State is a JSON file written atomically.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import duckdb
import httpx

from .findings import finding_uid, to_finding
from .rules import CompiledRule

log = logging.getLogger("detection_rules")


class Sink(Protocol):
    def send(self, findings: list[dict[str, Any]]) -> None: ...


class HubSink:
    """POST findings as NDJSON to the Watchfloor hub's OCSF ingest endpoint."""

    def __init__(self, hub_url: str, token: str, client: httpx.Client | None = None) -> None:
        if not hub_url or not token:
            raise ValueError("sending findings needs RULES_HUB_URL and RULES_INGEST_TOKEN (or use --dry-run)")
        self._url = f"{hub_url.rstrip('/')}/api/ingest/ocsf"
        self._headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/x-ndjson"}
        self._client = client or httpx.Client(timeout=15.0)

    def send(self, findings: list[dict[str, Any]]) -> None:
        body = "\n".join(json.dumps(f, separators=(",", ":")) for f in findings)
        r = self._client.post(self._url, content=body.encode(), headers=self._headers)
        r.raise_for_status()
        data = r.json()
        if data.get("rejected"):
            raise RuntimeError(f"hub rejected {data['rejected']} findings (contract mismatch?)")


class PrintSink:
    def __init__(self, write: Callable[[str], Any] = print) -> None:
        self._write = write

    def send(self, findings: list[dict[str, Any]]) -> None:
        for f in findings:
            self._write(json.dumps(f, separators=(",", ":")))


@dataclass
class State:
    watermark: int | None = None
    emitted: dict[str, int] = field(default_factory=dict)  # finding uid -> source event time

    @classmethod
    def load(cls, path: Path) -> State:
        try:
            doc = json.loads(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return cls()
        except (OSError, ValueError) as exc:
            log.warning("state file %s unreadable (%s); starting fresh", path, exc)
            return cls()
        return cls(watermark=doc.get("watermark"), emitted=dict(doc.get("emitted") or {}))

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"watermark": self.watermark, "emitted": self.emitted}), encoding="utf-8")
        os.replace(tmp, path)


@dataclass
class CycleResult:
    since: int
    until: int
    hits: int = 0
    sent: int = 0
    per_rule: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def run_cycle(rules: Iterable[CompiledRule], con: duckdb.DuckDBPyConnection, sink: Sink, state: State, *,
              now_ms: int, lookback_s: int, overlap_s: int, max_per_rule: int = 200) -> CycleResult:
    since = (state.watermark - overlap_s * 1000) if state.watermark is not None else now_ms - lookback_s * 1000
    res = CycleResult(since=since, until=now_ms)
    new: list[tuple[str, int, dict[str, Any]]] = []
    for rule in rules:
        try:
            cur = con.execute(rule.sql, [since, now_ms])
            cols = [d[0] for d in cur.description]
            rows = [dict(zip(cols, r, strict=True)) for r in cur.fetchmany(max_per_rule)]
        except duckdb.Error as exc:
            res.errors.append(f"{rule.id}: {exc}")
            log.error("rule %s (%s) failed: %s", rule.title, rule.id, exc)
            continue
        res.hits += len(rows)
        for row in rows:
            uid = finding_uid(rule.id, str(row["uid"]))
            if uid in state.emitted:
                continue
            new.append((uid, int(row["time"]), to_finding(rule, row, now_ms=now_ms)))
            res.per_rule[rule.id] = res.per_rule.get(rule.id, 0) + 1
    if new:
        sink.send([f for _, _, f in new])  # raises: state is not advanced, the next cycle retries the same window
        res.sent = len(new)
        state.emitted.update({uid: t for uid, t, _ in new})
    state.watermark = now_ms
    next_since = now_ms - overlap_s * 1000  # nothing older than this is read again
    state.emitted = {k: v for k, v in state.emitted.items() if v >= next_since}
    return res


def watch(rules: list[CompiledRule], open_con: Callable[[], duckdb.DuckDBPyConnection], sink: Sink,
          state_file: Path, *, interval_s: float, lookback_s: int, overlap_s: int, max_per_rule: int,
          cycles: int | None = None, clock: Callable[[], float] | None = None,
          sleep: Callable[[float], None] | None = None) -> list[CycleResult]:
    """Run cycles every ``interval_s`` (forever unless ``cycles`` is given). A failed cycle is logged and retried."""
    clock = clock or time.time
    sleep = sleep or time.sleep
    results = []
    n = 0
    while cycles is None or n < cycles:
        n += 1
        state = State.load(state_file)
        try:
            con = open_con()
            try:
                r = run_cycle(rules, con, sink, state, now_ms=int(clock() * 1000), lookback_s=lookback_s,
                              overlap_s=overlap_s, max_per_rule=max_per_rule)
            finally:
                con.close()
            state.save(state_file)
            results.append(r)
            log.info("cycle %d: %d hits, %d new findings sent%s", n, r.hits, r.sent,
                     f", {len(r.errors)} rule errors" if r.errors else "")
        except (httpx.HTTPError, RuntimeError, OSError, duckdb.Error) as exc:
            log.error("cycle %d failed, will retry the same window: %s", n, exc)
        if cycles is None or n < cycles:
            sleep(interval_s)
    return results
