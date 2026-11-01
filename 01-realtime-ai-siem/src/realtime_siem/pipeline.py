"""The processing pipeline: datagram -> syslog parse -> ECS -> detections -> chains -> sinks.

``Pipeline.ingest`` is synchronous and fast (pure CPU, no network) so it can run
inline in the UDP worker. LLM summarisation is the only slow step; it is exposed
separately (``summarize_chain``) so the server can run it in a worker thread
without blocking ingestion.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .config import Settings
from .correlation import AlertChain, ChainCorrelator
from .detections import DetectionEngine
from .ecs import ECS_VERSION, ECSValidationError, iso, set_path, to_ecs, validate
from .llm import ChainSummary, Summarizer
from .sinks import NdjsonSink
from .syslog_parser import parse_syslog

logger = logging.getLogger("realtime_siem.pipeline")


@dataclass(frozen=True)
class ChainSnapshot:
    """Point-in-time copy of an alert chain, safe to hand to a summariser thread."""
    chain_id: str
    key: str
    first_seen: datetime
    last_seen: datetime
    alert_ids: list[str]
    payload: dict[str, Any]


@dataclass
class Stats:
    """Running counters for the pipeline, reported periodically and at shutdown."""
    received: int = 0
    rejected_source: int = 0
    dropped_queue_full: int = 0
    parse_failures: int = 0
    schema_errors: int = 0
    events: int = 0
    alerts: int = 0
    chains_summarized: int = 0
    llm_fallbacks: int = 0
    by_format: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        """Return the counters as a plain dict for logging or JSON output."""
        return dict(self.__dict__)


class Pipeline:
    """Synchronous core of the SIEM: parse, normalise, detect, correlate and write.

    The network server feeds raw datagrams in; this class owns the detection engine,
    the chain correlator and the three NDJSON sinks (events, alerts, chains).
    """
    def __init__(self, settings: Settings, summarizer: Summarizer) -> None:
        self.s = settings
        self.summarizer = summarizer
        self.engine = DetectionEngine(settings)
        self.correlator = ChainCorrelator(settings.chain_window_s, settings.chain_min_alerts,
                                          settings.chain_resummarize_s)
        out = settings.output_dir
        kw = {"directory": out, "max_bytes": settings.rotate_max_bytes, "backup_count": settings.rotate_backup_count}
        self.events_sink = NdjsonSink("events", **kw)
        self.alerts_sink = NdjsonSink("alerts", **kw)
        self.chains_sink = NdjsonSink("chains", **kw)
        self.stats = Stats()
        self._stats_lock = threading.Lock()

    def ingest(self, data: bytes, peer: tuple[str, int], received_at: datetime | None = None
               ) -> list[AlertChain]:
        """Process one datagram. Returns chains that are due for an LLM summary."""
        received_at = received_at or datetime.now(timezone.utc)
        msg = parse_syslog(data, received_at=received_at, default_tz=self.s.default_timezone)
        self.stats.by_format[msg.format] = self.stats.by_format.get(msg.format, 0) + 1
        if msg.format == "unknown":
            self.stats.parse_failures += 1
        try:
            event = to_ecs(msg, peer_ip=peer[0], peer_port=peer[1])
        except ECSValidationError as exc:
            # Should be unreachable; recorded so a mapping bug is visible, never silent.
            self.stats.schema_errors += 1
            logger.error("ECS validation failed for datagram from %s: %s", peer[0], exc)
            return []
        self.events_sink.write(event)
        self.stats.events += 1

        due: list[AlertChain] = []
        for alert in self.engine.process(event):
            self.alerts_sink.write(alert)
            self.stats.alerts += 1
            logger.info("ALERT %s", alert["message"])
            chain = self.correlator.add(alert)
            if chain is not None and chain not in due:
                due.append(chain)
        return due

    def snapshot(self, chain: AlertChain) -> ChainSnapshot:
        """Freeze a chain's current state. Call on the ingest thread before summarising elsewhere."""
        ChainCorrelator.mark_summarized(chain, chain.last_seen or datetime.now(timezone.utc))
        return ChainSnapshot(
            chain_id=chain.id, key=chain.key,
            first_seen=chain.first_seen or datetime.now(timezone.utc),
            last_seen=chain.last_seen or datetime.now(timezone.utc),
            alert_ids=[a["event"]["id"] for a in chain.alerts][-100:],
            payload=chain.to_payload(),
        )

    def summarize_snapshot(self, snap: ChainSnapshot) -> dict[str, Any]:
        """Summarise a frozen chain (slow: may call the LLM) and write the ECS chain document.

        Safe to run in a worker thread: it touches only the immutable snapshot,
        the summariser, and the thread-safe logging-based sink.
        """
        result = self.summarizer.summarize(snap.payload)
        doc = chain_document(snap, result)
        self.chains_sink.write(doc)
        with self._stats_lock:
            self.stats.chains_summarized += 1
            if result.fallback_reason:
                self.stats.llm_fallbacks += 1
        logger.info("CHAIN %s (%s alerts, %s via %s): %s", snap.chain_id, snap.payload["alert_count"],
                    result.verdict, result.provider, result.summary)
        return doc

    def summarize_chain(self, chain: AlertChain) -> dict[str, Any]:
        """Snapshot ``chain`` and summarise it synchronously (used by tests and replay)."""
        return self.summarize_snapshot(self.snapshot(chain))

    def flush(self) -> None:
        """Flush every sink to disk."""
        for sink in (self.events_sink, self.alerts_sink, self.chains_sink):
            sink.flush()

    def close(self) -> None:
        """Close every sink."""
        for sink in (self.events_sink, self.alerts_sink, self.chains_sink):
            sink.close()


def chain_document(snap: ChainSnapshot, result: ChainSummary) -> dict[str, Any]:
    """Build the ECS document written to ``chains.ndjson`` for one summarised chain."""
    payload = snap.payload
    doc: dict[str, Any] = {}
    now = datetime.now(timezone.utc)
    set_path(doc, "@timestamp", iso(snap.last_seen))
    set_path(doc, "ecs.version", ECS_VERSION)
    set_path(doc, "message", result.summary)
    set_path(doc, "event.id", str(uuid.uuid4()))
    set_path(doc, "event.kind", "alert")
    set_path(doc, "event.category", ["intrusion_detection"])
    set_path(doc, "event.type", ["indicator"])
    set_path(doc, "event.module", "realtime_siem")
    set_path(doc, "event.dataset", "realtime_siem.chains")
    set_path(doc, "event.severity", payload["max_severity"])
    set_path(doc, "event.risk_score", float(payload["max_severity"]))
    set_path(doc, "event.start", iso(snap.first_seen))
    set_path(doc, "event.end", iso(snap.last_seen))
    set_path(doc, "event.created", iso(now))
    set_path(doc, "rule.name", "Correlated alert chain")
    set_path(doc, "rule.ruleset", "realtime-siem")
    set_path(doc, "threat.framework", "MITRE ATT&CK")
    set_path(doc, "threat.technique.id", payload["techniques"])
    set_path(doc, "source.ip", snap.key if _looks_ip(snap.key) else None)
    set_path(doc, "related.ip", [snap.key] if _looks_ip(snap.key) else [])
    set_path(doc, "related.user", payload["users"])
    set_path(doc, "related.hosts", payload["hosts"])
    set_path(doc, "siem.chain.id", snap.chain_id)
    set_path(doc, "siem.chain.alert_ids", snap.alert_ids)
    set_path(doc, "siem.chain.alert_count", payload["alert_count"])
    set_path(doc, "siem.chain.rule_ids", payload["rule_ids"])
    set_path(doc, "siem.chain.attack_stage", result.attack_stage)
    set_path(doc, "siem.chain.verdict", result.verdict)
    set_path(doc, "siem.chain.summary", result.summary)
    set_path(doc, "siem.chain.recommended_actions", result.recommended_actions)
    set_path(doc, "siem.chain.llm.provider", result.provider)
    set_path(doc, "siem.chain.llm.model", result.model)
    set_path(doc, "siem.chain.llm.latency_ms", result.latency_ms)
    set_path(doc, "siem.chain.llm.fallback_reason", result.fallback_reason)
    validate(doc)
    return doc


def _looks_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
