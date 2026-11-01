"""SQLite persistence: incidents, a tamper-evident audit trail, and MTTR metrics.

Why SQLite: a single-file ACID store with zero operational overhead, which is
right-sized for one bot instance and survives container restarts on a volume.
WAL mode lets the HTTP threads read while a worker writes.

Concurrency guarantee that HitL depends on: every state transition is a
*compare-and-set* (``UPDATE ... WHERE id=? AND status=?``). If two analysts
click "Approve" at the same moment, or Slack retries a callback, exactly one
transition wins and the remediation runs exactly once.
"""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import statistics
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id                TEXT PRIMARY KEY,
    external_id       TEXT,
    title             TEXT NOT NULL,
    severity          TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    source            TEXT NOT NULL,
    host              TEXT,
    indicator_ip      TEXT,
    description       TEXT,
    enrichment        TEXT NOT NULL DEFAULT '{}',
    risk_score        INTEGER NOT NULL DEFAULT 0,
    status            TEXT NOT NULL,
    approval_nonce    TEXT NOT NULL,
    chat_provider     TEXT,
    chat_channel      TEXT,
    chat_message_ref  TEXT,
    decided_by        TEXT,
    remediation_output TEXT,
    detected_at       REAL NOT NULL,
    created_at        REAL NOT NULL,
    approval_requested_at REAL,
    decided_at        REAL,
    remediation_started_at REAL,
    resolved_at       REAL,
    updated_at        REAL NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_incidents_external ON incidents(source, external_id)
    WHERE external_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_incidents_status ON incidents(status);

CREATE TABLE IF NOT EXISTS audit_log (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    incident_id TEXT,
    actor       TEXT NOT NULL,
    event       TEXT NOT NULL,
    details     TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL
);

-- Audit rows are append-only: the database itself refuses edits and deletes.
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
"""

# Allowed transitions of the incident state machine.
TRANSITIONS: dict[str, set[str]] = {
    "new": {"awaiting_approval", "closed"},
    "awaiting_approval": {"approved", "rejected", "expired"},
    "approved": {"remediating"},
    "remediating": {"remediated", "failed"},
    "rejected": {"closed"},
    "expired": {"closed"},
    "failed": {"closed"},
    "remediated": {"closed"},
    "closed": set(),
}

GENESIS_HASH = "0" * 64


@dataclass
class Incident:
    """One incident row. ``approval_nonce`` is a capability token and is never exposed by the API."""
    id: str
    external_id: str | None
    title: str
    severity: str
    source: str
    host: str | None
    indicator_ip: str | None
    description: str | None
    enrichment: dict[str, Any]
    risk_score: int
    status: str
    approval_nonce: str
    chat_provider: str | None
    chat_channel: str | None
    chat_message_ref: str | None
    decided_by: str | None
    remediation_output: str | None
    detected_at: float
    created_at: float
    approval_requested_at: float | None
    decided_at: float | None
    remediation_started_at: float | None
    resolved_at: float | None
    updated_at: float

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Incident:
        """Build an incident from a SQLite row, decoding the JSON enrichment column."""
        data = dict(row)
        data["enrichment"] = json.loads(data["enrichment"] or "{}")
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dict for the API, without the approval nonce."""
        d = dict(self.__dict__)
        d.pop("approval_nonce")  # a capability token: never expose it over the API
        return d


class TransitionError(RuntimeError):
    """Raised when a transition is not allowed by the state machine."""


class Database:
    """SQLite store for incidents and a tamper-evident, hash-chained audit log.

    Each call opens a short-lived connection (WAL mode), so the class is safe to
    share between threads. ``clock`` is injectable for tests.
    """
    def __init__(self, path: Path, clock=time.time) -> None:
        self.path = Path(path)
        self.clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._audit_lock = threading.Lock()
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)
            conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Yield a configured SQLite connection and close it afterwards."""
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        try:
            yield conn
        finally:
            conn.close()

    # -- incidents -----------------------------------------------------------
    def create_incident(self, *, title: str, severity: str, source: str, detected_at: float,
                        external_id: str | None = None, host: str | None = None,
                        indicator_ip: str | None = None, description: str | None = None,
                        enrichment: dict[str, Any] | None = None, risk_score: int = 0) -> tuple[Incident, bool]:
        """Insert an incident. Returns (incident, created). Duplicate (source, external_id) is idempotent."""
        now = self.clock()
        if external_id:
            existing = self.find_by_external(source, external_id)
            if existing:
                return existing, False
        incident_id = f"INC-{time.strftime('%Y%m%d', time.gmtime(now))}-{uuid.uuid4().hex[:8].upper()}"
        with self.connect() as conn:
            try:
                conn.execute(
                    """INSERT INTO incidents (id, external_id, title, severity, source, host, indicator_ip,
                       description, enrichment, risk_score, status, approval_nonce, detected_at, created_at,
                       updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (incident_id, external_id, title, severity, source, host, indicator_ip, description,
                     json.dumps(enrichment or {}, default=str), risk_score, "new", uuid.uuid4().hex,
                     detected_at, now, now))
            except sqlite3.IntegrityError:
                # Lost a race with a concurrent duplicate delivery.
                existing = self.find_by_external(source, external_id or "")
                if existing:
                    return existing, False
                raise
        self.audit(incident_id, "system", "incident_created",
                   {"title": title, "severity": severity, "source": source, "external_id": external_id})
        return self.get(incident_id), True

    def get(self, incident_id: str) -> Incident:
        """Return one incident.

        Raises:
            KeyError: if no incident has that id.
        """
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if row is None:
            raise KeyError(incident_id)
        return Incident.from_row(row)

    def find_by_external(self, source: str, external_id: str) -> Incident | None:
        """Return the incident created from ``(source, external_id)``, if any (used for deduplication)."""
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE source=? AND external_id=?",
                               (source, external_id)).fetchone()
        return Incident.from_row(row) if row else None

    def list(self, status: str | None = None, limit: int = 100) -> list[Incident]:
        """List incidents, newest first, optionally filtered by status."""
        with self.connect() as conn:
            if status:
                rows = conn.execute("SELECT * FROM incidents WHERE status=? ORDER BY created_at DESC LIMIT ?",
                                    (status, limit)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [Incident.from_row(r) for r in rows]

    def transition(self, incident_id: str, expected: str, new: str, actor: str,
                   **fields: Any) -> bool:
        """Atomically move ``expected`` -> ``new``. Returns False if another actor got there first."""
        if new not in TRANSITIONS.get(expected, set()):
            raise TransitionError(f"{expected} -> {new} is not a valid transition")
        allowed = {"decided_by", "decided_at", "approval_requested_at", "remediation_started_at",
                   "resolved_at", "remediation_output", "chat_provider", "chat_channel", "chat_message_ref"}
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"cannot set {unknown} during a transition")
        now = self.clock()
        sets = ", ".join([f"{k}=?" for k in fields] + ["status=?", "updated_at=?"])
        params = [*fields.values(), new, now, incident_id, expected]
        with self.connect() as conn:
            cur = conn.execute(f"UPDATE incidents SET {sets} WHERE id=? AND status=?", params)  # noqa: S608 - column names are allow-listed above
        if cur.rowcount != 1:
            return False
        self.audit(incident_id, actor, f"status:{expected}->{new}",
                   {k: v for k, v in fields.items() if k != "remediation_output"})
        return True

    def update_chat_ref(self, incident_id: str, provider: str, channel: str, message_ref: str) -> None:
        """Remember where the approval card was posted so it can be updated later."""
        with self.connect() as conn:
            conn.execute("UPDATE incidents SET chat_provider=?, chat_channel=?, chat_message_ref=?, updated_at=? "
                         "WHERE id=?", (provider, channel, message_ref, self.clock(), incident_id))

    def awaiting_older_than(self, cutoff: float) -> list[Incident]:
        """Return incidents still awaiting approval that were requested before ``cutoff``."""
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM incidents WHERE status='awaiting_approval' "
                                "AND approval_requested_at < ?", (cutoff,)).fetchall()
        return [Incident.from_row(r) for r in rows]

    # -- audit ---------------------------------------------------------------
    def audit(self, incident_id: str | None, actor: str, event: str, details: dict[str, Any]) -> None:
        """Append a hash-chained audit record: hash = sha256(prev_hash || canonical record)."""
        ts = self.clock()
        body = json.dumps(details, sort_keys=True, default=str, separators=(",", ":"))
        with self._audit_lock, self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
                prev = row["hash"] if row else GENESIS_HASH
                digest = _audit_hash(prev, ts, incident_id, actor, event, body)
                conn.execute("INSERT INTO audit_log (ts, incident_id, actor, event, details, prev_hash, hash) "
                             "VALUES (?,?,?,?,?,?,?)", (ts, incident_id, actor, event, body, prev, digest))
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def audit_trail(self, incident_id: str | None = None) -> list[dict[str, Any]]:
        """Return audit entries in sequence order, for one incident or for all of them."""
        with self.connect() as conn:
            if incident_id:
                rows = conn.execute("SELECT * FROM audit_log WHERE incident_id=? ORDER BY seq",
                                    (incident_id,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM audit_log ORDER BY seq").fetchall()
        return [dict(r) for r in rows]

    def verify_audit_chain(self) -> tuple[bool, int | None]:
        """Recompute every hash. Returns (ok, first_bad_seq)."""
        prev = GENESIS_HASH
        for r in self.audit_trail():
            expected = _audit_hash(prev, r["ts"], r["incident_id"], r["actor"], r["event"], r["details"])
            if r["prev_hash"] != prev or r["hash"] != expected:
                return False, r["seq"]
            prev = r["hash"]
        return True, None

    # -- metrics -------------------------------------------------------------
    def mttr_report(self, since: float | None = None) -> dict[str, Any]:
        """Mean/median/p90 for the response-time KPIs, overall and by severity.

        * time_to_acknowledge: detected  -> first human decision (approve/reject)
        * approval_latency:   approval requested -> decision (pure human wait)
        * time_to_contain:    decision -> remediation finished (automation speed)
        * mttr:               detected  -> resolved (remediated, or closed as a false positive)
        """
        clause, params = ("WHERE detected_at >= ?", (since,)) if since else ("", ())
        with self.connect() as conn:
            rows = [dict(r) for r in conn.execute(f"SELECT * FROM incidents {clause}", params)]  # noqa: S608 - static clause
        by_sev: dict[str, list[dict]] = {}
        for r in rows:
            by_sev.setdefault(r["severity"], []).append(r)
        status_counts: dict[str, int] = {}
        for r in rows:
            status_counts[r["status"]] = status_counts.get(r["status"], 0) + 1
        return {
            "incidents": len(rows),
            "by_status": status_counts,
            "overall": _kpis(rows),
            "by_severity": {sev: _kpis(items) for sev, items in sorted(by_sev.items())},
        }


def _audit_hash(prev: str, ts: float, incident_id: str | None, actor: str, event: str, body: str) -> str:
    material = json.dumps([prev, repr(ts), incident_id, actor, event, body], separators=(",", ":"))
    return hashlib.sha256(material.encode()).hexdigest()


def _stats(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"count": 0, "mean_s": None, "median_s": None, "p90_s": None}
    ordered = sorted(values)
    p90 = ordered[math.ceil(0.9 * len(ordered)) - 1]  # nearest-rank percentile
    return {"count": len(values), "mean_s": round(statistics.fmean(values), 2),
            "median_s": round(statistics.median(values), 2), "p90_s": round(p90, 2)}


def _kpis(rows: list[dict[str, Any]]) -> dict[str, Any]:
    def span(a: str, b: str, status: set[str] | None = None) -> list[float]:
        """Durations ``row[b] - row[a]`` for rows where both timestamps are set and the status matches."""
        return [r[b] - r[a] for r in rows
                if r[a] is not None and r[b] is not None and (status is None or r["status"] in status)]
    return {
        "time_to_acknowledge": _stats(span("detected_at", "decided_at")),
        "approval_latency": _stats(span("approval_requested_at", "decided_at")),
        "time_to_contain": _stats(span("decided_at", "resolved_at", {"remediated"})),
        "mttr": _stats(span("detected_at", "resolved_at")),
    }
