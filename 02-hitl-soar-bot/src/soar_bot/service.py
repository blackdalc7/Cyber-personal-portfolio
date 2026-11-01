"""Orchestration of the Human-in-the-Loop flow.

    alert ──► incident(new) ──► enrich + score ──► awaiting_approval ──► chat card with buttons
                                                        │
                       analyst clicks (signed callback) │  no click within TTL
                     ┌──────────────────────────────────┴───────────────┐
                 approve                     reject                  expired
                     │                         │                       │
               approved ─► remediating ─► remediated | failed     (escalate)
                     ▲
          the ONLY path that executes the remediation script

"Waiting for the callback" is durable state in SQLite rather than a blocked
thread: the bot can restart while an approval is pending and the button still works.
"""

from __future__ import annotations

import hmac
import json
import logging
import threading
import time
from concurrent.futures import Executor, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from .chat.base import APPROVE, REJECT, ChatError, ChatProvider
from .db import Database, Incident
from .decision_hook import DecisionWebhook
from .enrichment import Enricher, risk_score
from .ingest import SEVERITIES, NormalisedAlert
from .remediation import Remediator

logger = logging.getLogger("soar_bot.service")


@dataclass
class DecisionOutcome:
    """Result of an approve or reject click: whether it was accepted, and a message for the user."""
    accepted: bool
    message: str
    incident: Incident | None = None


class SoarService:
    """The human-in-the-loop workflow: alert, incident, approval card, decision, isolation.

    Isolation only runs after an allow-listed analyst approves with the incident's
    current nonce, and every state change is written to the audit log.
    """
    def __init__(self, db: Database, chat: ChatProvider, enricher: Enricher, remediator: Remediator,
                 approvers: frozenset[str], approval_ttl_s: int = 3600, min_severity: str = "medium",
                 executor: Executor | None = None, clock=time.time,
                 decision_hook: DecisionWebhook | None = None) -> None:
        self.db = db
        self.chat = chat
        self.enricher = enricher
        self.remediator = remediator
        self.approvers = approvers
        self.approval_ttl_s = approval_ttl_s
        self.min_severity = min_severity
        self.executor = executor or ThreadPoolExecutor(max_workers=4, thread_name_prefix="soar")
        self.clock = clock
        self.decision_hook = decision_hook
        self._stop = threading.Event()

    # -- intake ----------------------------------------------------------------
    def handle_alert(self, alert: NormalisedAlert) -> tuple[Incident, bool]:
        """Enrich and store an alert, then request approval when policy requires it.

        Returns:
            ``(incident, created)``; ``created`` is False for a duplicate alert.
        """
        intel = self.enricher.enrich(alert.indicator_ip)
        incident, created = self.db.create_incident(
            title=alert.title, severity=alert.severity, source=alert.source, detected_at=alert.detected_at,
            external_id=alert.external_id, host=alert.host, indicator_ip=alert.indicator_ip,
            description=alert.description, enrichment=intel, risk_score=risk_score(alert.severity, intel))
        if not created:
            logger.info("Duplicate alert %s/%s -> %s", alert.source, alert.external_id, incident.id)
            return incident, False

        if SEVERITIES.index(incident.severity) < SEVERITIES.index(self.min_severity):
            self.db.transition(incident.id, "new", "closed", "policy", resolved_at=self.clock())
            self.db.audit(incident.id, "policy", "auto_closed", {"reason": f"below {self.min_severity}"})
            return self.db.get(incident.id), True
        if not incident.host:
            # Nothing to isolate: still notify, but there is no approval to grant.
            self.db.audit(incident.id, "policy", "no_isolatable_host", {})

        self.db.transition(incident.id, "new", "awaiting_approval", "system", approval_requested_at=self.clock())
        incident = self.db.get(incident.id)
        try:
            channel, ref = self.chat.send_approval_request(incident)
            self.db.update_chat_ref(incident.id, self.chat.name, channel, ref)
            self.db.audit(incident.id, "system", "approval_requested", {"provider": self.chat.name,
                                                                        "channel": channel})
        except ChatError as exc:
            # The incident stays awaiting_approval and visible via the API; expiry escalates it.
            logger.error("Could not post approval request for %s: %s", incident.id, exc)
            self.db.audit(incident.id, "system", "chat_delivery_failed", {"error": str(exc)})
        return self.db.get(incident.id), True

    # -- human decision --------------------------------------------------------
    def decide(self, incident_id: str, nonce: str, decision: str, user_id: str, user_name: str,
               provider: str) -> DecisionOutcome:
        """Apply an analyst's button click. Safe against replays, double clicks and forged values."""
        actor = f"{provider}:{user_id}"
        try:
            incident = self.db.get(incident_id)
        except KeyError:
            return DecisionOutcome(False, "Unknown incident.")
        if not hmac.compare_digest(incident.approval_nonce, nonce):
            self.db.audit(incident_id, actor, "decision_rejected", {"reason": "nonce_mismatch"})
            return DecisionOutcome(False, "This approval link is not valid.", incident)
        if user_id not in self.approvers:
            self.db.audit(incident_id, actor, "decision_rejected", {"reason": "not_an_approver", "name": user_name})
            logger.warning("Unauthorised approval attempt on %s by %s (%s)", incident_id, user_name, actor)
            return DecisionOutcome(False, "You are not authorised to approve containment actions.", incident)
        if decision == APPROVE and not incident.host:
            return DecisionOutcome(False, "This incident has no host to isolate.", incident)

        now = self.clock()
        if decision == APPROVE:
            won = self.db.transition(incident_id, "awaiting_approval", "approved", actor,
                                     decided_by=user_name, decided_at=now)
        elif decision == REJECT:
            won = self.db.transition(incident_id, "awaiting_approval", "rejected", actor,
                                     decided_by=user_name, decided_at=now, resolved_at=now)
        else:
            return DecisionOutcome(False, "Unknown decision.", incident)

        incident = self.db.get(incident_id)
        if not won:
            return DecisionOutcome(False, f"Already handled ({incident.status}).", incident)
        # Update the card before queuing remediation so a fast worker can never be overwritten
        # by this older "approved" status.
        self._safe_update(incident)
        self._notify(incident)
        if decision == APPROVE:
            self.executor.submit(self._remediate, incident_id)
        return DecisionOutcome(True, "Isolation approved." if decision == APPROVE else "Isolation rejected.",
                               incident)

    def _remediate(self, incident_id: str) -> None:
        if not self.db.transition(incident_id, "approved", "remediating", "system",
                                  remediation_started_at=self.clock()):
            return
        incident = self.db.get(incident_id)
        self._safe_update(incident)
        try:
            result = self.remediator.isolate(incident.id, incident.host, incident.indicator_ip)
        except Exception as exc:  # the worker must always reach a terminal state
            logger.exception("Remediation crashed for %s", incident_id)
            ok, output = False, f'{{"error": "{type(exc).__name__}"}}'
        else:
            ok, output = result.ok, json.dumps({"exit_code": result.exit_code, **result.output})
        self.db.transition(incident_id, "remediating", "remediated" if ok else "failed", "system",
                           resolved_at=self.clock() if ok else None, remediation_output=output)
        incident = self.db.get(incident_id)
        self._safe_update(incident)
        self._notify(incident)

    # -- expiry ----------------------------------------------------------------
    def expire_stale(self) -> list[str]:
        """Mark approvals older than the TTL as expired and update their cards."""
        expired = []
        for incident in self.db.awaiting_older_than(self.clock() - self.approval_ttl_s):
            if self.db.transition(incident.id, "awaiting_approval", "expired", "system"):
                expired.append(incident.id)
                current = self.db.get(incident.id)
                self._safe_update(current)
                self._notify(current)
        return expired

    def run_expiry_loop(self, interval_s: float) -> threading.Thread:
        """Start a daemon thread that expires stale approval requests every ``interval_s``."""
        def loop() -> None:
            """Sweep until :meth:`shutdown` is called, logging and surviving errors."""
            while not self._stop.wait(interval_s):
                try:
                    self.expire_stale()
                except Exception:
                    logger.exception("expiry sweep failed")
        t = threading.Thread(target=loop, name="soar-expiry", daemon=True)
        t.start()
        return t

    def shutdown(self) -> None:
        """Stop the expiry loop and wait for running remediations to finish."""
        self._stop.set()
        self.executor.shutdown(wait=True)

    def _safe_update(self, incident: Incident) -> None:
        try:
            self.chat.update(incident)
        except ChatError as exc:
            logger.warning("Chat update failed for %s: %s", incident.id, exc)

    def _notify(self, incident: Incident) -> None:
        """Send the decision webhook off the request path; the outcome goes into the audit trail."""
        hook = self.decision_hook
        if hook is None:
            return

        def send() -> None:
            ok = hook.deliver(incident)
            self.db.audit(incident.id, "system", "decision_webhook_sent" if ok else "decision_webhook_failed",
                          {"event": f"incident.{incident.status}"})

        self.executor.submit(send)

    def metrics(self, since: float | None = None) -> dict[str, Any]:
        """Return MTTA and MTTR statistics, optionally only since ``since``."""
        return self.db.mttr_report(since)
