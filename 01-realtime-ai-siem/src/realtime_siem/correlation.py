"""Alert-chain correlation.

Individual alerts are noisy; an analyst cares about the *story*. This module
groups alerts that share an attacker source IP (``source.ip``) into a chain and
decides when a chain is worth an LLM summary:

* the chain holds at least ``chain_min_alerts`` alerts, and
* it has grown since the last summary, and
* either its severity escalated (e.g. high -> critical) or the debounce
  interval ``chain_resummarize_s`` has passed.

Chains idle for longer than ``chain_window_s`` are closed and evicted.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from .detections import SEVERITY_SCORES, parse_ts
from .ecs import get_path


@dataclass
class AlertChain:
    """All alerts seen from one attacker key (usually ``source.ip``), plus summary bookkeeping.

    The ``summarized_*`` fields record the state of the chain when it was last sent
    to the summariser, so the correlator can tell whether it has changed since.
    """
    key: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    alerts: list[dict[str, Any]] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    summarized_count: int = 0
    summarized_severity: int = 0
    summarized_at: datetime | None = None

    @property
    def max_severity(self) -> int:
        """Highest ECS ``event.severity`` across the chain's alerts (0 when empty)."""
        return max((get_path(a, "event.severity", 0) for a in self.alerts), default=0)

    @property
    def rule_ids(self) -> list[str]:
        """Distinct rule ids in the chain, in first-seen order."""
        seen: list[str] = []
        for a in self.alerts:
            rid = get_path(a, "rule.id")
            if rid and rid not in seen:
                seen.append(rid)
        return seen

    def technique_ids(self) -> list[str]:
        """Distinct MITRE ATT&CK technique ids in the chain, in first-seen order."""
        out: list[str] = []
        for a in self.alerts:
            for t in get_path(a, "threat.technique.id", []) or []:
                if t not in out:
                    out.append(t)
        return out

    def to_payload(self, max_alerts: int = 25) -> dict[str, Any]:
        """Compact, LLM-friendly view of the chain (bounded so token cost is predictable)."""
        alerts = self.alerts if len(self.alerts) <= max_alerts else self.alerts[:5] + self.alerts[-(max_alerts - 5):]
        return {
            "chain_id": self.id,
            "source_ip": self.key,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "alert_count": len(self.alerts),
            "max_severity": self.max_severity,
            "rule_ids": self.rule_ids,
            "techniques": self.technique_ids(),
            "hosts": sorted({h for a in self.alerts for h in (get_path(a, "related.hosts", []) or [])}),
            "users": sorted({u for a in self.alerts for u in (get_path(a, "related.user", []) or [])}),
            "alerts": [
                {
                    "time": get_path(a, "@timestamp"),
                    "rule": f"{get_path(a, 'rule.id')} {get_path(a, 'rule.name')}",
                    "severity": get_path(a, "event.severity"),
                    "reason": get_path(a, "event.reason"),
                    "host": get_path(a, "host.hostname"),
                    "users": get_path(a, "related.user", []),
                }
                for a in alerts
            ],
        }


class ChainCorrelator:
    """Group alerts into per-source chains and decide when each chain needs a summary.

    Args:
        window_s: idle time after which a chain is closed and evicted.
        min_alerts: a chain needs at least this many alerts before it is summarised.
        resummarize_s: minimum gap between two summaries of the same chain, unless
            its severity escalates.
        max_chains: hard cap on open chains; the least recently active are evicted first.
    """
    def __init__(self, window_s: int, min_alerts: int, resummarize_s: int, max_chains: int = 10_000) -> None:
        self.window = timedelta(seconds=window_s)
        self.min_alerts = min_alerts
        self.resummarize = timedelta(seconds=resummarize_s)
        self.max_chains = max_chains
        self.chains: dict[str, AlertChain] = {}

    def _expire(self, now: datetime) -> None:
        """Drop chains idle for longer than the window, then enforce ``max_chains``."""
        stale = [k for k, c in self.chains.items() if c.last_seen and now - c.last_seen > self.window]
        for k in stale:
            del self.chains[k]
        while len(self.chains) > self.max_chains:
            oldest = min(self.chains, key=lambda k: self.chains[k].last_seen or now)
            del self.chains[oldest]

    def add(self, alert: dict[str, Any]) -> AlertChain | None:
        """Add an alert; return its chain when the chain is due for (re)summarisation."""
        key = get_path(alert, "source.ip") or get_path(alert, "host.hostname") or "unknown"
        ts = parse_ts(alert["@timestamp"])
        self._expire(ts)
        chain = self.chains.get(key)
        if chain is None:
            chain = self.chains[key] = AlertChain(key=key)
        chain.alerts.append(alert)
        chain.first_seen = min(chain.first_seen or ts, ts)
        chain.last_seen = max(chain.last_seen or ts, ts)
        return chain if self._due(chain, ts) else None

    def _due(self, chain: AlertChain, now: datetime) -> bool:
        """True when ``chain`` has grown and either escalated or passed the debounce interval."""
        if len(chain.alerts) < self.min_alerts or len(chain.alerts) <= chain.summarized_count:
            return False
        if chain.summarized_at is None or chain.max_severity > chain.summarized_severity:
            return True
        return now - chain.summarized_at >= self.resummarize

    @staticmethod
    def mark_summarized(chain: AlertChain, now: datetime) -> None:
        """Record that ``chain`` was summarised at ``now`` in its current state."""
        chain.summarized_count = len(chain.alerts)
        chain.summarized_severity = chain.max_severity
        chain.summarized_at = now


def severity_label(score: int) -> str:
    """Map a numeric ECS severity score to its label (low, medium, high or critical)."""
    for name, value in sorted(SEVERITY_SCORES.items(), key=lambda kv: -kv[1]):
        if score >= value:
            return name
    return "low"
