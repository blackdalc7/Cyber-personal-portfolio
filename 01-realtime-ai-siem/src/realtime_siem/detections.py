"""Streaming, stateful detection engine.

The engine sees one ECS event at a time (real-time, no batch re-scans) and keeps
bounded sliding-window state per entity:

=============  =================================================  ===========================
Rule           Logic                                              ATT&CK
=============  =================================================  ===========================
SIEM-AUTH-001  >= N auth failures from one source in W seconds    T1110.001 Password Guessing
SIEM-AUTH-002  auth success from a source that tripped AUTH-001   T1110.001 + T1078
SIEM-AUTH-003  >= M distinct usernames failing from one source    T1110.003 Password Spraying
SIEM-PRIV-001  sudo / account creation / group change on a host   T1548.003 / T1136.001 / T1098
               within P seconds of an AUTH-002 compromise
=============  =================================================  ===========================

Memory is bounded: windows are pruned on every event and the number of tracked
keys is capped with LRU eviction, so a spoofed-source flood cannot exhaust RAM.
"""

from __future__ import annotations

import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Generic, TypeVar

from .config import Settings
from .ecs import ECS_VERSION, get_path, iso, set_path, validate

SEVERITY_SCORES = {"low": 21, "medium": 47, "high": 73, "critical": 99}

T = TypeVar("T")


class BoundedDict(OrderedDict, Generic[T]):
    """An LRU-ordered dict that evicts the least recently touched key past ``maxlen``."""

    def __init__(self, maxlen: int) -> None:
        super().__init__()
        self.maxlen = maxlen

    def touch(self, key: Any, factory: Any) -> T:
        """Return the value for ``key``, creating it with ``factory()`` if absent, and mark it recently used."""
        if key in self:
            self.move_to_end(key)
        else:
            self[key] = factory()
            if len(self) > self.maxlen:
                self.popitem(last=False)
        return self[key]


@dataclass(frozen=True)
class RuleMeta:
    """Static metadata for one detection rule, copied into every alert it raises."""
    id: str
    name: str
    severity: str
    tactic_ids: tuple[str, ...]
    tactic_names: tuple[str, ...]
    technique_ids: tuple[str, ...]
    technique_names: tuple[str, ...]
    description: str


RULES: dict[str, RuleMeta] = {
    "SIEM-AUTH-001": RuleMeta(
        "SIEM-AUTH-001", "Authentication brute force", "high",
        ("TA0006",), ("Credential Access",), ("T1110.001",), ("Brute Force: Password Guessing",),
        "Repeated authentication failures from a single source inside the detection window."),
    "SIEM-AUTH-002": RuleMeta(
        "SIEM-AUTH-002", "Successful login after brute force", "critical",
        ("TA0006", "TA0001"), ("Credential Access", "Initial Access"),
        ("T1110.001", "T1078"), ("Brute Force: Password Guessing", "Valid Accounts"),
        "A source that was brute forcing authenticated successfully: treat the account as compromised."),
    "SIEM-AUTH-003": RuleMeta(
        "SIEM-AUTH-003", "Password spraying", "high",
        ("TA0006", "TA0007"), ("Credential Access", "Discovery"),
        ("T1110.003", "T1087"), ("Brute Force: Password Spraying", "Account Discovery"),
        "One source tried many distinct usernames inside the detection window."),
    "SIEM-PRIV-001": RuleMeta(
        "SIEM-PRIV-001", "Privileged activity after compromise", "critical",
        ("TA0004", "TA0003"), ("Privilege Escalation", "Persistence"),
        ("T1548.003", "T1136.001", "T1098"),
        ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Create Account: Local Account",
         "Account Manipulation"),
        "Privileged action on a host shortly after a brute-force compromise of that host."),
}


def parse_ts(value: str) -> datetime:
    """Parse an ISO 8601 timestamp, accepting a trailing ``Z`` for UTC."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass
class _Compromise:
    """A source/host pair that logged in successfully after a brute-force alert."""
    at: datetime
    alert_id: str
    source_ip: str
    user: str | None


class DetectionEngine:
    """Feed ECS events in with :meth:`process`; get ECS alert documents out."""

    def __init__(self, settings: Settings) -> None:
        self.s = settings
        cap = settings.max_tracked_keys
        self._failures: BoundedDict[deque] = BoundedDict(cap)        # src_ip -> deque[(ts, user, event_id)]
        self._bf_tripped: BoundedDict[datetime] = BoundedDict(cap)   # src_ip -> ts of last AUTH-001
        self._compromised: BoundedDict[_Compromise] = BoundedDict(cap)  # host -> compromise
        self._cooldown: BoundedDict[datetime] = BoundedDict(cap)     # (rule, key) -> last fired
        self.alert_count = 0

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def _prune(window: deque, cutoff: datetime) -> None:
        """Pop timestamps older than ``cutoff`` from the left of a sliding window."""
        while window and window[0][0] < cutoff:
            window.popleft()

    def _cooling(self, rule_id: str, key: str, now: datetime) -> bool:
        """True if ``rule_id`` already fired for ``key`` within the cooldown; otherwise start a new cooldown."""
        last = self._cooldown.get((rule_id, key))
        if last is not None and now - last < timedelta(seconds=self.s.alert_cooldown_s):
            return True
        self._cooldown.touch((rule_id, key), lambda: now)
        self._cooldown[(rule_id, key)] = now
        return False

    def _alert(self, rule_id: str, *, reason: str, start: datetime,
               end: datetime, source_ip: str | None, users: list[str], host: str | None,
               evidence_ids: list[str]) -> dict[str, Any]:
        """Build a schema-valid ECS alert document for ``rule_id``."""
        meta = RULES[rule_id]
        doc: dict[str, Any] = {}
        set_path(doc, "@timestamp", iso(end))
        set_path(doc, "ecs.version", ECS_VERSION)
        set_path(doc, "message", f"[{meta.severity.upper()}] {meta.name}: {reason}")
        set_path(doc, "event.id", str(uuid.uuid4()))
        set_path(doc, "event.kind", "alert")
        set_path(doc, "event.category", ["intrusion_detection"])
        set_path(doc, "event.type", ["indicator"])
        set_path(doc, "event.module", "realtime_siem")
        set_path(doc, "event.dataset", "realtime_siem.alerts")
        set_path(doc, "event.severity", SEVERITY_SCORES[meta.severity])
        set_path(doc, "event.risk_score", float(SEVERITY_SCORES[meta.severity]))
        set_path(doc, "event.reason", reason)
        set_path(doc, "event.start", iso(start))
        set_path(doc, "event.end", iso(end))
        set_path(doc, "rule.id", meta.id)
        set_path(doc, "rule.name", meta.name)
        set_path(doc, "rule.description", meta.description)
        set_path(doc, "rule.ruleset", "realtime-siem")
        set_path(doc, "rule.category", meta.severity)
        set_path(doc, "threat.framework", "MITRE ATT&CK")
        set_path(doc, "threat.tactic.id", list(meta.tactic_ids))
        set_path(doc, "threat.tactic.name", list(meta.tactic_names))
        set_path(doc, "threat.technique.id", list(meta.technique_ids))
        set_path(doc, "threat.technique.name", list(meta.technique_names))
        set_path(doc, "source.ip", source_ip)
        set_path(doc, "user.name", users[0] if len(users) == 1 else None)
        set_path(doc, "host.hostname", host)
        set_path(doc, "related.ip", [source_ip] if source_ip else [])
        set_path(doc, "related.user", sorted(set(users)))
        set_path(doc, "related.hosts", [host] if host else [])
        set_path(doc, "siem.alert.evidence_count", len(evidence_ids))
        set_path(doc, "siem.alert.trigger_event_ids", evidence_ids[-50:])
        validate(doc)
        self.alert_count += 1
        return doc

    # -- main entry point ----------------------------------------------------
    def process(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Run every rule against one ECS event.

        Returns:
            Zero or more new ECS alert documents raised by this event.
        """
        categories = get_path(event, "event.category", []) or []
        outcome = get_path(event, "event.outcome")
        src = get_path(event, "source.ip")
        user = get_path(event, "user.name")
        host = get_path(event, "host.hostname")
        event_id = get_path(event, "event.id", "")
        ts = parse_ts(event["@timestamp"])
        alerts: list[dict[str, Any]] = []

        if "authentication" in categories and src:
            if outcome == "failure":
                alerts.extend(self._on_failure(event, ts, src, user, host, event_id))
            elif outcome == "success":
                alerts.extend(self._on_success(event, ts, src, user, host, event_id))

        if host and self._is_privileged(event):
            alerts.extend(self._on_privileged(event, ts, user, host, event_id))
        return alerts

    def _on_failure(self, event, ts, src, user, host, event_id):
        """Track a failed login for the brute-force (AUTH-001) and spraying (AUTH-003) rules."""
        alerts = []
        window = self._failures.touch(src, deque)
        window.append((ts, user, event_id))
        self._prune(window, ts - timedelta(seconds=max(self.s.brute_force_window_s, self.s.spray_window_s)))

        bf_cut = ts - timedelta(seconds=self.s.brute_force_window_s)
        bf = [e for e in window if e[0] >= bf_cut]
        if len(bf) >= self.s.brute_force_threshold:
            self._bf_tripped.touch(src, lambda: ts)
            self._bf_tripped[src] = ts
            if not self._cooling("SIEM-AUTH-001", src, ts):
                users = sorted({e[1] for e in bf if e[1]})
                alerts.append(self._alert(
                    "SIEM-AUTH-001",
                    reason=f"{len(bf)} failed logins from {src} in {self.s.brute_force_window_s}s "
                           f"against {len(users)} account(s)",
                    start=bf[0][0], end=ts, source_ip=src, users=users, host=host,
                    evidence_ids=[e[2] for e in bf]))

        spray_cut = ts - timedelta(seconds=self.s.spray_window_s)
        spray = [e for e in window if e[0] >= spray_cut and e[1]]
        distinct = sorted({e[1] for e in spray})
        if len(distinct) >= self.s.spray_user_threshold and not self._cooling("SIEM-AUTH-003", src, ts):
            alerts.append(self._alert(
                "SIEM-AUTH-003",
                reason=f"{src} tried {len(distinct)} distinct usernames in {self.s.spray_window_s}s",
                start=spray[0][0], end=ts, source_ip=src, users=distinct[:50], host=host,
                evidence_ids=[e[2] for e in spray]))
        return alerts

    def _on_success(self, event, ts, src, user, host, event_id):
        """Raise AUTH-002 when a source that tripped AUTH-001 then logs in successfully."""
        tripped = self._bf_tripped.get(src)
        if tripped is None or ts - tripped > timedelta(seconds=self.s.brute_force_window_s):
            return []
        window = self._failures.get(src) or deque()
        prior = [e for e in window if e[0] >= ts - timedelta(seconds=self.s.brute_force_window_s)]
        alert = self._alert(
            "SIEM-AUTH-002",
            reason=f"{len(prior)} failures from {src} then a SUCCESSFUL login as '{user}'",
            start=prior[0][0] if prior else ts, end=ts, source_ip=src,
            users=[user] if user else [], host=host,
            evidence_ids=[e[2] for e in prior] + [event_id])
        if host:
            self._compromised.touch(host, lambda: None)
            self._compromised[host] = _Compromise(ts, get_path(alert, "event.id"), src, user)
        return [alert]

    @staticmethod
    def _is_privileged(event: dict[str, Any]) -> bool:
        """True for sudo, account creation and group-membership change events."""
        action = get_path(event, "event.action")
        outcome = get_path(event, "event.outcome")
        categories = get_path(event, "event.category", []) or []
        if outcome != "success":
            return False
        if action == "sudo" and "process" in categories:
            return True
        return action in {"user_created", "user_added_to_group", "added-user-account",
                          "added-member-to-group", "logged-in-special"}

    def _on_privileged(self, event, ts, user, host, event_id):
        """Raise PRIV-001 for privileged activity on a host compromised within the window."""
        comp = self._compromised.get(host)
        if comp is None or not (timedelta(0) <= ts - comp.at <= timedelta(seconds=self.s.post_compromise_window_s)):
            return []
        action = get_path(event, "event.action")
        detail = get_path(event, "process.command_line") or get_path(event, "user.target.name") or action
        # De-duplicate per (host, action, detail) so a burst of identical sudo calls is one alert.
        if self._cooling("SIEM-PRIV-001", f"{host}|{action}|{detail}", ts):
            return []
        users = sorted({u for u in (user, comp.user, get_path(event, "user.target.name")) if u})
        return [self._alert(
            "SIEM-PRIV-001",
            reason=f"{action} ({detail}) on {host} {int((ts - comp.at).total_seconds())}s after "
                   f"compromise from {comp.source_ip}",
            start=comp.at, end=ts, source_ip=comp.source_ip, users=users, host=host,
            evidence_ids=[comp.alert_id, event_id])]
