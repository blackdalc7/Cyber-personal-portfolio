"""Outbound, signed decision webhook: tell the rest of the platform what a human decided.

When an analyst approves or rejects, and when the remediation it started finishes (or an approval expires), the
bot POSTs a small JSON event to ``DECISION_WEBHOOK_URL``. n8n uses it to start evidence collection (09) after an
approved containment and to notify the channel. The body is signed exactly like inbound alerts, with
``DECISION_WEBHOOK_SECRET``:

    X-SOAR-Timestamp: <unix seconds>
    X-SOAR-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>." + body>
    X-SOAR-Event:     incident.approved | incident.rejected | incident.remediated | incident.failed | incident.expired

The receiver must verify the signature and reject stale timestamps; ``verify_body`` in :mod:`soar_bot.ingest` does
both. The event never contains the approval nonce, so a leaked webhook cannot be turned into a click.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from typing import Any

import requests

from .db import Incident
from .ingest import sign_body

logger = logging.getLogger("soar_bot.decision_hook")

EVENTS = {"approved", "rejected", "remediated", "failed", "expired"}
FIELDS = ("id", "external_id", "title", "severity", "source", "host", "indicator_ip", "status", "risk_score",
          "decided_by", "detected_at", "decided_at", "remediation_started_at", "resolved_at")


def event_body(incident: Incident, sent_at: float) -> dict[str, Any]:
    return {"event": f"incident.{incident.status}", "sent_at": sent_at,
            "incident": {k: getattr(incident, k) for k in FIELDS}}


class DecisionWebhook:
    """Deliver decision events with a few retries. Delivery problems are logged, never raised."""

    def __init__(self, url: str, secret: str, session: requests.Session | None = None, timeout_s: float = 10.0,
                 retries: int = 3, backoff_s: float = 1.0, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.time) -> None:
        self.url = url
        self._secret = secret
        self._http = session or requests.Session()
        self._timeout = timeout_s
        self._retries = retries
        self._backoff = backoff_s
        self._sleep = sleep
        self._clock = clock

    def deliver(self, incident: Incident) -> bool:
        """POST one event for the incident's current status. Returns True once the receiver answered 2xx."""
        if incident.status not in EVENTS:
            return False
        body = json.dumps(event_body(incident, self._clock()), separators=(",", ":"), sort_keys=True).encode()
        for attempt in range(self._retries):
            ts, sig = sign_body(self._secret, body, int(self._clock()))  # fresh timestamp per attempt
            try:
                r = self._http.post(self.url, data=body, timeout=self._timeout, headers={
                    "Content-Type": "application/json", "X-SOAR-Timestamp": ts, "X-SOAR-Signature": sig,
                    "X-SOAR-Event": f"incident.{incident.status}"})
                if r.status_code < 300:
                    return True
                if 400 <= r.status_code < 500 and r.status_code != 429:
                    logger.error("Decision webhook refused %s (%s); not retrying", incident.id, r.status_code)
                    return False
                reason = f"HTTP {r.status_code}"
            except requests.RequestException as exc:
                reason = type(exc).__name__
            logger.warning("Decision webhook attempt %d for %s failed: %s", attempt + 1, incident.id, reason)
            if attempt + 1 < self._retries:
                self._sleep(self._backoff * 2 ** attempt)
        return False
